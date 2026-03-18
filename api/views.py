from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
import jwt
from jwt import PyJWKClient
from datetime import timedelta
from django.db import IntegrityError
from django.db.models import Q
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
import random
import math
import traceback

from .models import (
    Trip, Route, Vehicle, PaymentDetails,
    ContactDetails, GroupDetails, UserDetails, SeatAvailability,
    Post, Follower, CompletedTrip, BoardingOTP,
    PostImage, PostLike, PostSave, UserSearchHistory,
    AppNotification,
)
from .serializers import (
    UserProfileSerializer, OtherUserProfileSerializer,
    TripSerializer, RouteSerializer, VehicleSerializer,
    PaymentDetailsSerializer, ContactDetailsSerializer, GroupDetailsSerializer,
    FeedPostSerializer, CreatePostSerializer,
)

SUPABASE_JWKS_URL  = 'https://tqmrytzypqsuxjwdrihh.supabase.co/auth/v1/.well-known/jwks.json'
OTP_EXPIRY_SECONDS = 600  # 10 minutes


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _verify_supabase_token(access_token: str) -> dict:
    try:
        jwks_client = PyJWKClient(SUPABASE_JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        decoded = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["ES256", "RS256", "HS256"],
            options={"verify_aud": False},
            leeway=timedelta(seconds=60),
        )
        return decoded
    except Exception as e:
        print(f"❌ JWT decode failed: {e}")
        raise


def _extract_name(decoded: dict):
    meta      = decoded.get('user_metadata', {})
    full_name = meta.get('full_name') or meta.get('name', '')
    if full_name:
        parts = full_name.strip().split(' ', 1)
        return parts[0], parts[1] if len(parts) > 1 else ''
    return (
        meta.get('first_name') or meta.get('given_name', ''),
        meta.get('last_name')  or meta.get('family_name', ''),
    )


def _get_or_fix_user_details(user, supabase_uid, email, name):
    try:
        return UserDetails.objects.get(user=user)
    except UserDetails.DoesNotExist:
        pass
    try:
        details = UserDetails.objects.get(supabase_uid=supabase_uid)
        if details.user != user:
            details.user  = user
            details.email = email
            details.save()
        return details
    except UserDetails.DoesNotExist:
        pass
    try:
        details              = UserDetails.objects.get(email=email)
        details.user         = user
        details.supabase_uid = supabase_uid
        details.save()
        return details
    except UserDetails.DoesNotExist:
        pass
    try:
        return UserDetails.objects.create(
            user=user, supabase_uid=supabase_uid, name=name, email=email)
    except IntegrityError:
        try:
            return UserDetails.objects.get(supabase_uid=supabase_uid)
        except UserDetails.DoesNotExist:
            return UserDetails.objects.get(email=email)


def _get_user_name(user):
    try:
        return user.details.name or f"{user.first_name} {user.last_name}".strip() or user.username
    except Exception:
        return f"{user.first_name} {user.last_name}".strip() or user.username


def _get_user_email(user):
    try:
        return user.details.email or user.email
    except Exception:
        return user.email


def _time_ago(dt):
    """Convert a datetime to a human-readable relative string."""
    now      = timezone.now()
    seconds  = int((now - dt).total_seconds())
    if seconds < 60:
        return 'just now'
    if seconds < 3600:
        return f'{seconds // 60}m ago'
    if seconds < 86400:
        return f'{seconds // 3600}h ago'
    if seconds < 604800:
        days = seconds // 86400
        return f'{days}d ago'
    return dt.strftime('%d %b')


def _create_notification(recipient, actor, verb,
                         target_type=None, target_id=None,
                         target_details=None, allow_self=False):
    if not allow_self and recipient == actor:
        return
    try:
        AppNotification.objects.create(
            recipient      = recipient,
            actor          = actor,
            verb           = verb,
            target_type    = target_type,
            target_id      = target_id,
            target_details = target_details or {},
        )
    except Exception:
        pass


# ── OTP SYSTEM ────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_otp(request):
    email = request.data.get('email', '').strip()
    if not email or '@' not in email:
        return Response({'error': 'Valid email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        otp       = str(random.randint(100000, 999999))
        cache_key = f'otp_email_{email}'
        cache.set(cache_key, otp, timeout=OTP_EXPIRY_SECONDS)

        send_mail(
            subject='Your Verification Code',
            message=(
                f'Your verification code is: {otp}\n\n'
                f'This code is valid for 10 minutes.\n'
                f'Do not share this code with anyone.'
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return Response({'message': f'OTP sent to {email}'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': f'Failed to send OTP: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_otp(request):
    email = request.data.get('email', '').strip()
    otp   = request.data.get('otp',   '').strip()

    if not email or not otp:
        return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

    cache_key  = f'otp_email_{email}'
    stored_otp = cache.get(cache_key)

    if stored_otp is None:
        return Response({'verified': False, 'error': 'OTP expired or not sent'}, status=status.HTTP_400_BAD_REQUEST)
    if stored_otp != otp:
        return Response({'verified': False, 'error': 'Incorrect OTP'}, status=status.HTTP_400_BAD_REQUEST)

    cache.delete(cache_key)
    return Response({'verified': True}, status=status.HTTP_200_OK)


# ── AUTH & PROFILE ────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    access_token = request.data.get('access_token')
    first_name   = request.data.get('first_name', '')
    last_name    = request.data.get('last_name',  '')

    if not access_token:
        return Response({'error': 'access_token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        decoded      = _verify_supabase_token(access_token)
        supabase_uid = decoded['sub']
        email        = decoded.get('email', '')

        if not first_name:
            first_name, last_name = _extract_name(decoded)

        name    = f"{first_name} {last_name}".strip() or email
        user, _ = User.objects.get_or_create(
            username=supabase_uid,
            defaults={'email': email, 'first_name': first_name, 'last_name': last_name},
        )
        _get_or_fix_user_details(user, supabase_uid, email, name)
        token, _ = Token.objects.get_or_create(user=user)

        return Response({'key': token.key, 'user_id': user.id}, status=status.HTTP_201_CREATED)
    except jwt.ExpiredSignatureError:
        return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError as e:
        return Response({'error': f'Invalid token: {e}'}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    access_token = request.data.get('access_token')
    if not access_token:
        return Response({'error': 'access_token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        decoded      = _verify_supabase_token(access_token)
        supabase_uid = decoded['sub']
        email        = decoded.get('email', '')

        first_name, last_name = _extract_name(decoded)
        name = f"{first_name} {last_name}".strip() or email

        user, created = User.objects.get_or_create(
            username=supabase_uid,
            defaults={'email': email, 'first_name': first_name, 'last_name': last_name},
        )
        user_details = _get_or_fix_user_details(user, supabase_uid, email, name)
        token, _     = Token.objects.get_or_create(user=user)

        return Response({
            'key':        token.key,
            'user_id':    user.id,
            'first_name': user_details.name,
            'email':      user.email,
            'created':    created,
        }, status=status.HTTP_200_OK)
    except jwt.ExpiredSignatureError:
        return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError as e:
        return Response({'error': f'Invalid token: {e}'}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    if request.method == 'GET':
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

    if request.method == 'PATCH':
        try:
            user_details    = request.user.details
            bio             = request.data.get('bio')
            profile_picture = request.data.get('profile_picture')

            if bio is not None:
                user_details.bio = bio
            if profile_picture is not None:
                user_details.profile_picture = profile_picture

            user_details.save()
            return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)
        except UserDetails.DoesNotExist:
            return Response({'error': 'User details not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def other_user_profile(request, user_id):
    try:
        target_user  = User.objects.get(id=user_id)
        is_following = Follower.objects.filter(
            follower=request.user, following=target_user).exists()

        serializer    = OtherUserProfileSerializer(target_user)
        response_data = dict(serializer.data)

        posts = Post.objects.filter(user=target_user).select_related('trip').order_by('-created_at')
        posts_data = []
        for post in posts:
            post_data = {
                'id':         post.id,
                'image_url':  post.image_url,
                'caption':    post.caption,
                'created_at': post.created_at,
                'trip': {
                    'id':          post.trip.id,
                    'destination': post.trip.destination,
                    'start_date':  post.trip.start_date,
                    'end_date':    post.trip.end_date,
                    'status':      getattr(post.trip, 'status', 'upcoming'),
                } if post.trip else None,
            }
            posts_data.append(post_data)

        response_data['posts']          = posts_data
        response_data['is_following']   = is_following
        response_data['is_own_profile'] = (request.user.id == target_user.id)

        return Response(response_data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        traceback.print_exc()
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def follow_user(request, user_id):
    try:
        target_user = User.objects.get(id=user_id)
        if target_user == request.user:
            return Response({'error': 'Cannot follow yourself'}, status=status.HTTP_400_BAD_REQUEST)

        follow, created = Follower.objects.get_or_create(
            follower=request.user, following=target_user)
        if not created:
            follow.delete()
            return Response({'following': False, 'message': 'Unfollowed'}, status=status.HTTP_200_OK)

        _create_notification(
            recipient=target_user,
            actor=request.user,
            verb='started following you',
        )

        return Response({'following': True, 'message': 'Followed'}, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_followers(request, user_id):
    try:
        target_user    = User.objects.get(id=user_id)
        follower_ids   = set()
        followers_list = []

        for follow in Follower.objects.filter(following=target_user).select_related('follower'):
            follower = follow.follower
            if follower.id == target_user.id or follower.id in follower_ids:
                continue
            follower_ids.add(follower.id)
            try:
                details = follower.details
                followers_list.append({
                    'id':              follower.id,
                    'username':        details.name,
                    'email':           follower.email,
                    'profile_picture': details.profile_picture,
                    'bio':             details.bio,
                })
            except UserDetails.DoesNotExist:
                followers_list.append({
                    'id':              follower.id,
                    'username':        f"{follower.first_name} {follower.last_name}".strip() or follower.username,
                    'email':           follower.email,
                    'profile_picture': None,
                    'bio':             '',
                })
        return Response(followers_list, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_following(request, user_id):
    try:
        target_user    = User.objects.get(id=user_id)
        following_ids  = set()
        following_list = []

        for follow in Follower.objects.filter(follower=target_user).select_related('following'):
            followed = follow.following
            if followed.id == target_user.id or followed.id in following_ids:
                continue
            following_ids.add(followed.id)
            try:
                details = followed.details
                following_list.append({
                    'id':              followed.id,
                    'username':        details.name,
                    'email':           followed.email,
                    'profile_picture': details.profile_picture,
                    'bio':             details.bio,
                })
            except UserDetails.DoesNotExist:
                following_list.append({
                    'id':              followed.id,
                    'username':        f"{followed.first_name} {followed.last_name}".strip() or followed.username,
                    'email':           followed.email,
                    'profile_picture': None,
                    'bio':             '',
                })
        return Response(following_list, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ── NOTIFICATIONS ─────────────────────────────────────────────────────────────

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_notifications(request):
    notifications = (
        AppNotification.objects
        .filter(recipient=request.user)
        .select_related('actor', 'actor__details')
        .order_by('-created_at')[:50]
    )

    data = []
    for n in notifications:
        actor_avatar = None
        try:
            actor_avatar = n.actor.details.profile_picture
        except Exception:
            pass

        data.append({
            'id':             n.id,
            'actor_id':       n.actor.id,
            'actor_name':     _get_user_name(n.actor),
            'actor_avatar':   actor_avatar,
            'verb':           n.verb,
            'target_type':    n.target_type,
            'target_id':      n.target_id,
            'target_details': n.target_details,
            'read':           n.read,
            'timestamp':      n.created_at.isoformat(),
            'time_ago':       _time_ago(n.created_at),
        })

    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_unread_count(request):
    count = AppNotification.objects.filter(
        recipient=request.user, read=False).count()
    return Response({'count': count}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_all_notifications_read(request):
    AppNotification.objects.filter(
        recipient=request.user, read=False).update(read=True)
    return Response({'message': 'All notifications marked as read'}, status=status.HTTP_200_OK)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mark_notification_read(request, notif_id):
    try:
        notif      = AppNotification.objects.get(id=notif_id, recipient=request.user)
        notif.read = True
        notif.save()
        return Response({'message': 'Marked as read'}, status=status.HTTP_200_OK)
    except AppNotification.DoesNotExist:
        return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)


# ── GROUP MANAGEMENT ──────────────────────────────────────────────────────────

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_group_details(request, group_id):
    try:
        group   = GroupDetails.objects.get(id=group_id)
        members = []
        for uid in group.members_list:
            try:
                user        = User.objects.get(id=uid)
                user_detail = getattr(user, 'details', None)
                members.append({
                    'user_id':  user.id,
                    'name':     user_detail.name if user_detail else
                                f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email':    user.email,
                    'is_admin': user.id == group.admin.id,
                })
            except User.DoesNotExist:
                pass

        cancel_deadline = None
        price_per_head  = 0
        try:
            payment         = group.trip.payment_info
            cancel_deadline = payment.cancel_deadline.isoformat() if payment.cancel_deadline else None
            price_per_head  = payment.price_per_head or 0
        except Exception:
            pass

        return Response({
            'group_id':        group.id,
            'group_name':      group.group_name,
            'admin_id':        group.admin.id,
            'members':         members,
            'trip_id':         group.trip.id,
            'cancel_deadline': cancel_deadline,
            'price_per_head':  price_per_head,
        }, status=status.HTTP_200_OK)
    except GroupDetails.DoesNotExist:
        return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def rename_group(request, group_id):
    try:
        group = GroupDetails.objects.get(id=group_id)
        if group.admin != request.user:
            return Response({'error': 'Only admin can rename the group'},
                            status=status.HTTP_403_FORBIDDEN)
        new_name = request.data.get('group_name', '').strip()
        if not new_name:
            return Response({'error': 'Group name cannot be empty'},
                            status=status.HTTP_400_BAD_REQUEST)
        group.group_name = new_name
        group.save()
        return Response({'group_name': group.group_name}, status=status.HTTP_200_OK)
    except GroupDetails.DoesNotExist:
        return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ── TRIP CREATION FLOW ────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_trip(request):
    serializer = TripSerializer(data=request.data)
    if serializer.is_valid():
        trip = serializer.save(user=request.user)
        SeatAvailability.objects.create(
            trip=trip, total_seats=trip.passengers, available_seats=trip.passengers)
        try:
            user_details = request.user.details
            current_list = list(user_details.trips_registered)
            if trip.id not in current_list:
                current_list.append(trip.id)
                user_details.trips_registered = current_list
                user_details.save()
        except UserDetails.DoesNotExist:
            pass
        return Response(
            {'message': 'Trip saved successfully', 'trip_id': trip.id},
            status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_route(request):
    data    = request.data
    trip_id = data.get('trip_id')
    try:
        trip = Trip.objects.get(id=trip_id, user=request.user)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)

    route_data = {
        'trip':           trip.id,
        'start_location': data.get('start_location'),
        'stops':          data.get('stops', []),
        'start_datetime': data.get('start_datetime'),
        'end_datetime':   data.get('end_datetime'),
    }
    vehicle_data = {
        'trip':           trip.id,
        'vehicle_number': data.get('vehicle_number'),
        'vehicle_model':  data.get('vehicle_model'),
    }

    try:
        route_serializer = RouteSerializer(Route.objects.get(trip=trip), data=route_data)
    except Route.DoesNotExist:
        route_serializer = RouteSerializer(data=route_data)

    try:
        vehicle_serializer = VehicleSerializer(Vehicle.objects.get(trip=trip), data=vehicle_data)
    except Vehicle.DoesNotExist:
        vehicle_serializer = VehicleSerializer(data=vehicle_data)

    if route_serializer.is_valid() and vehicle_serializer.is_valid():
        route_serializer.save()
        vehicle_serializer.save()
        return Response({'message': 'Route and Vehicle details saved!'}, status=status.HTTP_200_OK)
    return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_payment(request):
    data           = request.data
    trip_id        = data.get('trip_id')
    payment_method = data.get('payment_method')
    details_map    = data.get('payment_details', {})
    try:
        trip = Trip.objects.get(id=trip_id, user=request.user)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)

    payment_data = {
        'trip':             trip.id,
        'price_per_head':   data.get('price_per_head'),
        'booking_deadline': data.get('booking_deadline'),
        'cancel_deadline':  data.get('cancel_deadline'),
        'payment_method':   payment_method,
        'upi_id':     details_map.get('upi_id')     if payment_method == 'UPI'  else None,
        'account_no': details_map.get('account_no') if payment_method == 'Bank' else None,
        'ifsc':       details_map.get('ifsc')       if payment_method == 'Bank' else None,
    }
    try:
        serializer = PaymentDetailsSerializer(
            PaymentDetails.objects.get(trip=trip), data=payment_data)
    except PaymentDetails.DoesNotExist:
        serializer = PaymentDetailsSerializer(data=payment_data)

    if serializer.is_valid():
        serializer.save()
        return Response({'message': 'Payment details saved!'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def save_contact(request):
    data    = request.data
    trip_id = data.get('trip_id')
    try:
        trip = Trip.objects.get(id=trip_id, user=request.user)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)

    contact_data = {
        'trip':              trip.id,
        'phone':             data.get('phone'),
        'email':             data.get('email'),
        'is_phone_verified': data.get('is_phone_verified', False),
        'is_email_verified': data.get('is_email_verified', False),
    }
    try:
        contact_serializer = ContactDetailsSerializer(
            ContactDetails.objects.get(trip=trip), data=contact_data)
    except ContactDetails.DoesNotExist:
        contact_serializer = ContactDetailsSerializer(data=contact_data)

    if contact_serializer.is_valid():
        contact_serializer.save()
        group, _ = GroupDetails.objects.get_or_create(
            trip=trip,
            defaults={
                'admin':         request.user,
                'group_name':    f"Trip to {trip.destination}",
                'members_count': 1,
                'members_list':  [request.user.id],
            },
        )
        return Response(
            {'message':    'Trip Published & Group Created!',
             'group_id':   group.id,
             'group_name': group.group_name},
            status=status.HTTP_201_CREATED)
    return Response(contact_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ── TRIP RETRIEVAL ────────────────────────────────────────────────────────────

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_trips(request):
    try:
        user_details   = request.user.details
        registered_ids = user_details.trips_registered
        if not registered_ids:
            return Response([], status=status.HTTP_200_OK)

        today   = timezone.now().date()
        results = []

        for trip in Trip.objects.filter(id__in=registered_ids).select_related('payment_info'):
            try:
                group      = trip.group_info
                group_name = group.group_name
                group_id   = group.id
                admin_id   = group.admin.id
            except GroupDetails.DoesNotExist:
                group_name = f"Trip to {trip.destination}"
                group_id   = None
                admin_id   = None

            saved_status = getattr(trip, 'status', 'upcoming')
            if saved_status == 'completed':
                trip_status = 'completed'
            elif saved_status == 'ongoing':
                trip_status = 'ongoing'
            elif trip.start_date > today:
                trip_status = 'upcoming'
            elif trip.start_date <= today <= trip.end_date:
                trip_status = 'ongoing'
            elif today > trip.end_date:
                trip_status = 'completed'
            else:
                trip_status = 'upcoming'

            cancel_deadline = None
            price_per_head  = 0
            try:
                payment         = trip.payment_info
                cancel_deadline = payment.cancel_deadline.isoformat() if payment.cancel_deadline else None
                price_per_head  = payment.price_per_head or 0
            except Exception:
                pass

            results.append({
                'id':              trip.id,
                'trip_id':         trip.id,
                'destination':     trip.destination,
                'start_date':      str(trip.start_date),
                'end_date':        str(trip.end_date),
                'vehicle':         trip.vehicle,
                'passengers':      trip.passengers,
                'group_name':      group_name,
                'group_id':        group_id,
                'admin_id':        admin_id,
                'status':          trip_status,
                'is_admin':        request.user.id == admin_id,
                'date':            str(trip.start_date),
                'last_message':    f"Trip to {trip.destination} is confirmed!",
                'time':            'Just now',
                'cancel_deadline': cancel_deadline,
                'price_per_head':  price_per_head,
            })
        return Response(results, status=status.HTTP_200_OK)
    except UserDetails.DoesNotExist:
        return Response({'error': 'User details not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_trip_detail(request, trip_id):
    try:
        trip = Trip.objects.get(id=trip_id)

        people_already = 0
        people_needed  = trip.passengers
        is_registered  = False
        try:
            group          = GroupDetails.objects.get(trip=trip)
            people_already = max(0, group.members_count - 1)
            people_needed  = max(0, trip.passengers - people_already)
            if request.user.id in group.members_list:
                is_registered = True
        except GroupDetails.DoesNotExist:
            pass

        price = '₹0'
        try:
            price = f'₹{trip.payment_info.price_per_head}'
        except Exception:
            pass

        vehicle_name = trip.vehicle
        try:
            vehicle_name = trip.vehicle_details.vehicle_model
        except Exception:
            pass

        start_location = ''
        start_str      = str(trip.start_date)
        try:
            start_location = trip.route.start_location
            if trip.route.start_datetime:
                start_str = trip.route.start_datetime.strftime('%d %b, %I:%M %p')
        except Exception:
            pass

        try:
            driver_name = trip.user.details.name
        except Exception:
            driver_name = trip.user.first_name or trip.user.username

        return Response({
            'id':             trip.id,
            'destination':    trip.destination,
            'start_date':     start_str,
            'end_date':       str(trip.end_date),
            'vehicle':        vehicle_name,
            'passengers':     trip.passengers,
            'price':          price,
            'people_needed':  people_needed,
            'max_capacity':   trip.passengers,
            'people_already': people_already,
            'driver_name':    driver_name,
            'user_id':        trip.user.id,
            'from':           start_location,
            'is_joined':      is_registered,
            'status':         trip.status,
        }, status=status.HTTP_200_OK)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_trips(request):
    try:
        trips = Trip.objects.exclude(user=request.user).order_by('-created_at').select_related(
            'vehicle_details', 'route', 'payment_info', 'seat_info')
        results = []

        for trip in trips:
            if not hasattr(trip, 'payment_info') or not hasattr(trip, 'route'):
                continue

            start_str      = 'Date not set'
            start_location = 'Unknown'

            if hasattr(trip, 'route'):
                start_location = trip.route.start_location
                if trip.route.start_datetime:
                    start_str = trip.route.start_datetime.strftime('%d %b, %I:%M %p')
                elif trip.start_date:
                    start_str = trip.start_date.strftime('%d %b')

            vehicle_name = (trip.vehicle_details.vehicle_model
                            if hasattr(trip, 'vehicle_details') else trip.vehicle)
            price        = (f"₹{trip.payment_info.price_per_head}"
                            if hasattr(trip, 'payment_info') else '₹0')

            max_capacity   = trip.passengers
            is_registered  = False
            people_already = 0

            try:
                group          = GroupDetails.objects.get(trip=trip)
                people_already = max(0, group.members_count - 1)
                if request.user.id in group.members_list:
                    is_registered = True
            except GroupDetails.DoesNotExist:
                pass

            try:
                driver_name = trip.user.details.name
            except (UserDetails.DoesNotExist, AttributeError):
                driver_name = trip.user.first_name or trip.user.username

            results.append({
                'id':             trip.id,
                'destination':    trip.destination,
                'start_date':     start_str,
                'vehicle':        vehicle_name,
                'people_needed':  max(0, max_capacity - people_already),
                'max_capacity':   max_capacity,
                'people_already': people_already,
                'price':          price,
                'driver_name':    driver_name,
                'user_id':        trip.user.id,
                'from':           start_location,
                'is_joined':      is_registered,
            })
        return Response(results, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_join(request):
    trip_id = request.data.get('trip_id')
    try:
        trip = Trip.objects.get(id=trip_id)
        user = request.user

        try:
            user_details = user.details
        except UserDetails.DoesNotExist:
            return Response(
                {'error': 'User profile not found. Please complete your profile first.'},
                status=status.HTTP_400_BAD_REQUEST)

        if user_details.trips_registered and trip.id in user_details.trips_registered:
            return Response(
                {'error': 'You have already joined this trip.'},
                status=status.HTTP_400_BAD_REQUEST)

        try:
            seat_info = SeatAvailability.objects.get(trip=trip)
        except SeatAvailability.DoesNotExist:
            return Response(
                {'error': 'Seat information missing.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if seat_info.available_seats <= 0:
            return Response({'error': 'Trip is full!'}, status=status.HTTP_400_BAD_REQUEST)

        seat_info.available_seats -= 1
        seat_info.save()

        group           = GroupDetails.objects.get(trip=trip)
        current_members = list(group.members_list)
        if user.id not in current_members:
            current_members.append(user.id)
            group.members_list  = current_members
            group.members_count = len(current_members)
            group.save()

        current_trips = list(user_details.trips_registered)
        current_trips.append(trip.id)
        user_details.trips_registered = current_trips
        user_details.save()

        _create_notification(
            recipient      = group.admin,
            actor          = user,
            verb           = 'joined your trip',
            target_type    = 'trip',
            target_id      = trip.id,
            target_details = {
                'destination': trip.destination,
                'start_date':  str(trip.start_date),
            },
        )

        return Response({
            'message':     'Joined successfully!',
            'group_id':    group.id,
            'group_name':  group.group_name,
            'admin_id':    group.admin.id,
            'destination': trip.destination,
        }, status=status.HTTP_200_OK)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except GroupDetails.DoesNotExist:
        return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_completed_trips(request):
    try:
        user = request.user
        try:
            user_details = user.details
        except UserDetails.DoesNotExist:
            return Response([], status=status.HTTP_200_OK)

        trip_ids = user_details.trips_registered or []
        today    = timezone.now().date()
        trips    = Trip.objects.filter(id__in=trip_ids).filter(
            Q(status='completed') | Q(end_date__lt=today)
        )

        completed_list = []
        for trip in trips:
            CompletedTrip.objects.get_or_create(
                user=user,
                trip=trip,
                defaults={
                    'destination': trip.destination,
                    'start_date':  trip.start_date,
                    'end_date':    trip.end_date,
                },
            )
            completed_list.append({
                'trip_id':     trip.id,
                'destination': trip.destination,
                'start_date':  trip.start_date,
                'end_date':    trip.end_date,
            })

        return Response(completed_list, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_postable_trips(request):
    """Return all trips the user is registered in (upcoming, ongoing, completed)."""
    try:
        user = request.user
        try:
            user_details = user.details
        except UserDetails.DoesNotExist:
            return Response([], status=status.HTTP_200_OK)

        trip_ids = user_details.trips_registered or []
        today    = timezone.now().date()
        trips    = Trip.objects.filter(id__in=trip_ids).order_by('start_date')

        result = []
        for trip in trips:
            saved = trip.status
            if saved == 'completed':
                trip_status = 'completed'
            elif saved == 'ongoing':
                trip_status = 'ongoing'
            elif trip.start_date > today:
                trip_status = 'upcoming'
            elif trip.start_date <= today <= trip.end_date:
                trip_status = 'ongoing'
            else:
                trip_status = 'completed'

            result.append({
                'trip_id':     trip.id,
                'destination': trip.destination,
                'start_date':  str(trip.start_date),
                'end_date':    str(trip.end_date),
                'status':      trip_status,
            })

        return Response(result, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ── TRIP CANCEL ───────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cancel_trip(request, trip_id):
    try:
        trip  = Trip.objects.get(id=trip_id)
        group = GroupDetails.objects.get(trip=trip)
        user  = request.user

        if user.id not in group.members_list:
            return Response({'error': 'You are not a member of this trip.'},
                            status=status.HTTP_403_FORBIDDEN)

        try:
            payment         = trip.payment_info
            cancel_deadline = payment.cancel_deadline
            price_per_head  = payment.price_per_head or 0
            payment_method  = payment.payment_method

            if payment_method == 'UPI' and payment.upi_id:
                refund_detail = f"UPI ID: {payment.upi_id}"
            elif payment_method == 'Bank' and payment.account_no:
                refund_detail = f"Bank Account: {payment.account_no} (IFSC: {payment.ifsc})"
            else:
                refund_detail = "original payment method"
        except PaymentDetails.DoesNotExist:
            cancel_deadline = None
            price_per_head  = 0
            refund_detail   = "original payment method"

        if cancel_deadline and timezone.now() > cancel_deadline:
            return Response(
                {'error': 'Cancellation deadline has passed. This trip can no longer be cancelled.'},
                status=status.HTTP_400_BAD_REQUEST)

        is_admin    = (user.id == group.admin.id)
        destination = trip.destination

        if is_admin:
            members_to_notify = []
            for uid in group.members_list:
                try:
                    member       = User.objects.get(id=uid)
                    member_name  = _get_user_name(member)
                    member_email = _get_user_email(member)
                    members_to_notify.append((member, member_name, member_email))
                except User.DoesNotExist:
                    pass

            for member, _, _ in members_to_notify:
                if member.id == user.id:
                    continue
                _create_notification(
                    recipient      = member,
                    actor          = user,
                    verb           = 'cancelled the trip',
                    target_type    = 'trip',
                    target_id      = trip.id,
                    target_details = {'destination': destination},
                )

            for member, _, _ in members_to_notify:
                try:
                    details = member.details
                    updated = [t for t in list(details.trips_registered) if t != trip.id]
                    details.trips_registered = updated
                    details.save()
                except Exception:
                    pass

            try:
                group.delete()
            except Exception:
                pass
            try:
                SeatAvailability.objects.filter(trip=trip).delete()
            except Exception:
                pass
            trip.delete()

            for _, member_name, member_email in members_to_notify:
                if not member_email:
                    continue
                try:
                    send_mail(
                        subject=f'Trip to {destination} has been cancelled',
                        message=(
                            f'Hi {member_name},\n\n'
                            f'The trip to {destination} has been cancelled by the admin.\n\n'
                            f'Refund Details:\n'
                            f'  Amount : ₹{price_per_head}\n'
                            f'  Method : {refund_detail}\n\n'
                            f'Your refund will be credited within 5–7 business days.\n\n'
                            f'— The SeeMe Team'
                        ),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[member_email],
                        fail_silently=True,
                    )
                except Exception:
                    pass

            return Response(
                {'message': f'Trip to {destination} cancelled. All members notified.'},
                status=status.HTTP_200_OK)

        else:
            member_name  = _get_user_name(user)
            member_email = _get_user_email(user)

            _create_notification(
                recipient      = group.admin,
                actor          = user,
                verb           = 'left the trip',
                target_type    = 'trip',
                target_id      = trip.id,
                target_details = {'destination': destination},
            )

            updated_members = [uid for uid in group.members_list if uid != user.id]
            group.members_list  = updated_members
            group.members_count = len(updated_members)
            group.save()

            try:
                seat_info = SeatAvailability.objects.get(trip=trip)
                seat_info.available_seats = min(
                    seat_info.total_seats, seat_info.available_seats + 1)
                seat_info.save()
            except SeatAvailability.DoesNotExist:
                pass

            try:
                details = user.details
                updated = [t for t in list(details.trips_registered) if t != trip.id]
                details.trips_registered = updated
                details.save()
            except Exception:
                pass

            if member_email:
                try:
                    send_mail(
                        subject=f'Your booking for trip to {destination} has been cancelled',
                        message=(
                            f'Hi {member_name},\n\n'
                            f'Your booking for the trip to {destination} has been cancelled.\n\n'
                            f'Refund Details:\n'
                            f'  Amount : ₹{price_per_head}\n'
                            f'  Method : {refund_detail}\n\n'
                            f'Your refund will be credited within 5–7 business days.\n\n'
                            f'— The SeeMe Team'
                        ),
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[member_email],
                        fail_silently=True,
                    )
                except Exception:
                    pass

            return Response(
                {'message': f'You have successfully left the trip to {destination}.'},
                status=status.HTTP_200_OK)

    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except GroupDetails.DoesNotExist:
        return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        traceback.print_exc()
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ── TRIP BOARDING OTP FLOW ────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_trip(request, trip_id):
    try:
        trip  = Trip.objects.get(id=trip_id)
        group = GroupDetails.objects.get(trip=trip)

        if group.admin != request.user:
            return Response({'error': 'Only admin can start the trip'},
                            status=status.HTTP_403_FORBIDDEN)

        admin_id     = group.admin.id
        trip_details = {
            'destination': trip.destination,
            'trip_id':     trip.id,
        }

        for user_id in group.members_list:
            if user_id == admin_id:
                continue
            try:
                member_user = User.objects.get(id=user_id)
                BoardingOTP.objects.get_or_create(
                    trip=trip,
                    user=member_user,
                    defaults={'otp': str(random.randint(1000, 9999))},
                )
                _create_notification(
                    recipient      = member_user,
                    actor          = request.user,
                    verb           = 'your trip has started',
                    target_type    = 'trip',
                    target_id      = trip.id,
                    target_details = trip_details,
                )
            except User.DoesNotExist:
                pass

        trip.status = 'ongoing'
        trip.save()

        AppNotification.objects.create(
            recipient      = request.user,
            actor          = request.user,
            verb           = 'started the trip',
            target_type    = 'trip',
            target_id      = trip.id,
            target_details = trip_details,
        )

        return Response({'message': 'Trip started'}, status=status.HTTP_200_OK)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except GroupDetails.DoesNotExist:
        return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_boarding_otps(request, trip_id):
    try:
        trip  = Trip.objects.get(id=trip_id)
        group = GroupDetails.objects.get(trip=trip)

        if group.admin != request.user:
            return Response({'error': 'Only admin can view boarding OTPs'},
                            status=status.HTTP_403_FORBIDDEN)

        admin_id     = group.admin.id
        members_data = []

        for user_id in group.members_list:
            if user_id == admin_id:
                continue
            try:
                user        = User.objects.get(id=user_id)
                user_detail = getattr(user, 'details', None)
                name        = user_detail.name if user_detail else \
                              f"{user.first_name} {user.last_name}".strip() or user.username

                try:
                    boarding = BoardingOTP.objects.get(trip=trip, user=user)
                    verified = boarding.verified
                except BoardingOTP.DoesNotExist:
                    verified = False

                members_data.append({
                    'user_id':  user_id,
                    'name':     name,
                    'verified': verified,
                    'is_admin': False,
                })
            except User.DoesNotExist:
                pass

        all_verified = all(m['verified'] for m in members_data) if members_data else False

        if all_verified and members_data and trip.status != 'completed':
            trip.status = 'completed'
            trip.save()

        return Response({
            'trip_id':      trip_id,
            'destination':  trip.destination,
            'status':       trip.status,
            'members':      members_data,
            'all_verified': all_verified,
        }, status=status.HTTP_200_OK)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_my_boarding_otp(request, trip_id):
    try:
        trip = Trip.objects.get(id=trip_id)
        user = request.user

        try:
            group = GroupDetails.objects.get(trip=trip)
            if group.admin.id == user.id:
                return Response(
                    {'error': 'Admin does not have a boarding OTP'},
                    status=status.HTTP_400_BAD_REQUEST)
        except GroupDetails.DoesNotExist:
            pass

        try:
            boarding = BoardingOTP.objects.get(trip=trip, user=user)
        except BoardingOTP.DoesNotExist:
            if trip.status == 'ongoing':
                otp_value = str(random.randint(1000, 9999))
                boarding  = BoardingOTP.objects.create(
                    trip=trip, user=user, otp=otp_value)
            else:
                return Response(
                    {'error': 'Trip has not started yet'},
                    status=status.HTTP_404_NOT_FOUND)

        return Response({
            'otp':         boarding.otp,
            'verified':    boarding.verified,
            'destination': trip.destination,
        }, status=status.HTTP_200_OK)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_member_boarding(request, trip_id, user_id):
    try:
        trip  = Trip.objects.get(id=trip_id)
        group = GroupDetails.objects.get(trip=trip)

        if group.admin != request.user:
            return Response({'error': 'Only admin can verify members'},
                            status=status.HTTP_403_FORBIDDEN)

        submitted_otp = request.data.get('otp', '').strip()
        if not submitted_otp:
            return Response({'error': 'OTP is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            member_user = User.objects.get(id=user_id)
            boarding    = BoardingOTP.objects.get(trip=trip, user=member_user)
        except BoardingOTP.DoesNotExist:
            return Response(
                {'error': 'OTP not found — member has not loaded their OTP yet'},
                status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

        if submitted_otp != boarding.otp:
            return Response({'verified': False, 'error': 'Incorrect OTP'},
                            status=status.HTTP_400_BAD_REQUEST)

        boarding.verified = True
        boarding.save()

        admin_id          = group.admin.id
        non_admin_members = [uid for uid in group.members_list if uid != admin_id]
        all_verified      = all(
            BoardingOTP.objects.filter(
                trip=trip, user_id=uid, verified=True).exists()
            for uid in non_admin_members
        )

        if all_verified and non_admin_members:
            trip.status = 'completed'
            trip.save()
            return Response({
                'verified':       True,
                'all_verified':   True,
                'trip_completed': True,
            }, status=status.HTTP_200_OK)

        return Response({'verified': True, 'all_verified': False}, status=status.HTTP_200_OK)
    except Trip.DoesNotExist:
        return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)
    except GroupDetails.DoesNotExist:
        return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ── POSTS ─────────────────────────────────────────────────────────────────────

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_post(request):
    trip_id     = request.data.get('trip_id')
    caption     = request.data.get('caption', '')
    location    = request.data.get('location', '')
    destination = request.data.get('destination', '')
    image_urls  = request.data.get('image_urls', [])

    trip = None
    if trip_id:
        try:
            trip = Trip.objects.get(id=trip_id)
            if not destination:
                destination = trip.destination
        except Trip.DoesNotExist:
            return Response({'error': 'Trip not found'}, status=status.HTTP_404_NOT_FOUND)

    if not image_urls:
        return Response({'error': 'At least one image is required'}, status=status.HTTP_400_BAD_REQUEST)

    post = Post.objects.create(
        user=request.user,
        trip=trip,
        caption=caption,
        location=location,
        destination=destination,
        image_url=image_urls[0],
    )
    for i, url in enumerate(image_urls):
        PostImage.objects.create(post=post, image_url=url, order=i)

    if trip:
        try:
            group = GroupDetails.objects.get(trip=trip)
            notif_details = {
                'destination': destination,
                'caption':     caption[:80] if caption else '',
                'image_url':   image_urls[0],
            }
            for uid in group.members_list:
                if uid == request.user.id:
                    continue
                try:
                    member = User.objects.get(id=uid)
                    _create_notification(
                        recipient      = member,
                        actor          = request.user,
                        verb           = 'posted in your trip',
                        target_type    = 'post',
                        target_id      = post.id,
                        target_details = notif_details,
                    )
                except User.DoesNotExist:
                    pass
        except GroupDetails.DoesNotExist:
            pass

    return Response({'message': 'Post created!', 'post_id': post.id}, status=status.HTTP_201_CREATED)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_post(request, post_id):
    try:
        post = Post.objects.get(id=post_id, user=request.user)
        post.delete()
        return Response({'message': 'Post deleted successfully'}, status=status.HTTP_200_OK)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_like(request, post_id):
    try:
        post = Post.objects.get(id=post_id)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found'}, status=status.HTTP_404_NOT_FOUND)

    like, created = PostLike.objects.get_or_create(user=request.user, post=post)
    if not created:
        like.delete()
    else:
        _create_notification(
            recipient      = post.user,
            actor          = request.user,
            verb           = 'liked your post',
            target_type    = 'post',
            target_id      = post.id,
            target_details = {
                'caption':   post.caption[:80] if post.caption else '',
                'image_url': post.image_url,
            },
        )

    return Response({'liked': created, 'like_count': post.likes.count()}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def toggle_save(request, post_id):
    try:
        post = Post.objects.get(id=post_id)
    except Post.DoesNotExist:
        return Response({'error': 'Post not found'}, status=status.HTTP_404_NOT_FOUND)
    save, created = PostSave.objects.get_or_create(user=request.user, post=post)
    if not created:
        save.delete()
    return Response({'saved': created}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_saved_posts(request):
    saved_ids  = PostSave.objects.filter(user=request.user).order_by('-created_at').values_list('post_id', flat=True)
    posts      = Post.objects.filter(id__in=saved_ids).select_related('user', 'user__details').prefetch_related('images', 'likes', 'saves')
    serializer = FeedPostSerializer(posts, many=True, context={'request': request})
    return Response(serializer.data, status=status.HTTP_200_OK)


# ── FEED ──────────────────────────────────────────────────────────────────────

def _rank_score(post, followed_ids, recent_destinations, now):
    hours_old         = max(0, (now - post.created_at).total_seconds() / 3600)
    is_followed_bonus = 50.0 if post.user_id in followed_ids else 0.0
    destination_bonus = 30.0 if (post.destination or '').lower() in recent_destinations else 0.0
    recency_score     = 30.0 * math.exp(-hours_old / 48.0)
    return is_followed_bonus + destination_bonus + recency_score


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_feed(request):
    page     = max(1, int(request.query_params.get('page', 1)))
    per_page = min(30, max(1, int(request.query_params.get('per_page', 10))))
    user     = request.user
    now      = timezone.now()

    followed_ids = set(
        Follower.objects.filter(follower=user).values_list('following_id', flat=True)
    )
    recent_destinations = {
        d.lower() for d in UserSearchHistory.objects
        .filter(user=user).order_by('-searched_at')
        .values_list('destination', flat=True)[:10]
    }

    posts  = (Post.objects.exclude(user=user)
              .select_related('user', 'user__details')
              .prefetch_related('images', 'likes', 'saves'))
    scored = sorted(posts, key=lambda p: _rank_score(p, followed_ids, recent_destinations, now), reverse=True)

    total      = len(scored)
    start      = (page - 1) * per_page
    page_posts = scored[start:start + per_page]

    serializer = FeedPostSerializer(page_posts, many=True, context={'request': request})
    return Response({
        'posts':    serializer.data,
        'page':     page,
        'per_page': per_page,
        'total':    total,
        'has_more': (start + per_page) < total,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def record_search(request):
    destination = request.data.get('destination', '').strip()
    if not destination:
        return Response({'error': 'destination is required'}, status=status.HTTP_400_BAD_REQUEST)
    UserSearchHistory.objects.create(user=request.user, destination=destination)
    old_ids = list(UserSearchHistory.objects.filter(user=request.user)
                   .order_by('-searched_at').values_list('id', flat=True)[20:])
    UserSearchHistory.objects.filter(id__in=old_ids).delete()
    return Response({'message': 'Recorded'}, status=status.HTTP_200_OK)