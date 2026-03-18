from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Trip, Route, Vehicle, PaymentDetails,
    ContactDetails, GroupDetails, UserDetails, Post, Follower,
    PostImage, PostLike, PostSave,
)


class UserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model  = UserDetails
        fields = ['name', 'email', 'phone', 'bio', 'profile_picture',
                  'trips_registered', 'trips_success']


class UserProfileSerializer(serializers.ModelSerializer):
    details         = UserDetailsSerializer(read_only=True)
    post_count      = serializers.SerializerMethodField()
    bio             = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = ['id', 'email', 'first_name', 'last_name', 'details',
                  'post_count', 'bio', 'profile_picture']

    def get_post_count(self, obj):
        return obj.posts.count()

    def get_bio(self, obj):
        return obj.details.bio if hasattr(obj, 'details') else ''

    def get_profile_picture(self, obj):
        return obj.details.profile_picture if hasattr(obj, 'details') else None


class PostSerializer(serializers.ModelSerializer):
    trip_destination = serializers.CharField(source='trip.destination', read_only=True)
    trip_start_date  = serializers.DateField(source='trip.start_date',  read_only=True)
    trip_end_date    = serializers.DateField(source='trip.end_date',    read_only=True)

    class Meta:
        model  = Post
        fields = ['id', 'image_url', 'caption', 'created_at', 'trip',
                  'trip_destination', 'trip_start_date', 'trip_end_date']


class OtherUserProfileSerializer(serializers.ModelSerializer):
    name            = serializers.SerializerMethodField()
    email           = serializers.EmailField()
    post_count      = serializers.SerializerMethodField()
    trip_count      = serializers.SerializerMethodField()
    trips           = serializers.SerializerMethodField()
    follower_count  = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()
    bio             = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model  = User
        fields = [
            'id', 'name', 'email',
            'post_count',
            # NOTE: 'posts' is intentionally excluded here.
            # The view (other_user_profile) always builds the posts list
            # itself with full trip detail and injects it into the response.
            'trip_count', 'trips',
            'follower_count', 'following_count',
            'bio', 'profile_picture',
        ]

    def get_name(self, obj):
        name = f"{obj.first_name} {obj.last_name}".strip()
        return name or obj.username

    def get_post_count(self, obj):
        return obj.posts.count()

    def get_trip_count(self, obj):
        try:
            return len(obj.details.trips_registered or [])
        except Exception:
            return 0

    def get_trips(self, obj):
        try:
            trip_ids = obj.details.trips_registered or []
            trips    = Trip.objects.filter(id__in=trip_ids)
            return [{
                'id':          t.id,
                'destination': t.destination,
                'start_date':  str(t.start_date),
                'end_date':    str(t.end_date),
                'status':      t.status,
            } for t in trips]
        except Exception:
            return []

    def get_follower_count(self, obj):
        return obj.followers.count()

    def get_following_count(self, obj):
        return obj.following.count()

    def get_bio(self, obj):
        return obj.details.bio if hasattr(obj, 'details') else ''

    def get_profile_picture(self, obj):
        return obj.details.profile_picture if hasattr(obj, 'details') else None


class TripSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Trip
        fields = ['id', 'destination', 'start_date', 'end_date', 'vehicle', 'passengers']


class RouteSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Route
        fields = ['trip', 'start_location', 'stops', 'start_datetime', 'end_datetime']


class VehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Vehicle
        fields = ['trip', 'vehicle_number', 'vehicle_model']


class PaymentDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model  = PaymentDetails
        fields = [
            'trip', 'price_per_head',
            'booking_deadline', 'cancel_deadline',
            'payment_method', 'upi_id', 'account_no', 'ifsc',
        ]


class ContactDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model  = ContactDetails
        fields = ['trip', 'phone', 'email', 'is_phone_verified', 'is_email_verified']


class GroupDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model  = GroupDetails
        fields = ['id', 'trip', 'group_name', 'admin', 'members_count', 'members_list']


class PostImageSerializer(serializers.ModelSerializer):
    class Meta:
        model  = PostImage
        fields = ['id', 'image_url', 'order']


class FeedPostSerializer(serializers.ModelSerializer):
    images         = serializers.SerializerMethodField()
    like_count     = serializers.SerializerMethodField()
    save_count     = serializers.SerializerMethodField()
    is_liked       = serializers.SerializerMethodField()
    is_saved       = serializers.SerializerMethodField()
    author_id      = serializers.SerializerMethodField()
    author_name    = serializers.SerializerMethodField()
    author_picture = serializers.SerializerMethodField()

    class Meta:
        model  = Post
        fields = [
            'id', 'caption', 'location', 'destination', 'created_at',
            'images',
            'like_count', 'save_count', 'is_liked', 'is_saved',
            'author_id', 'author_name', 'author_picture',
        ]

    def _user(self):
        return self.context.get('request').user

    def get_author_id(self, obj):
        return obj.user.id

    def get_author_name(self, obj):
        details = getattr(obj.user, 'details', None)
        if details and details.name:
            return details.name
        return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username

    def get_author_picture(self, obj):
        details = getattr(obj.user, 'details', None)
        return details.profile_picture if details else None

    def get_like_count(self, obj):
        return obj.likes.count()

    def get_save_count(self, obj):
        return obj.saves.count()

    def get_is_liked(self, obj):
        user = self._user()
        if not user or not user.is_authenticated:
            return False
        return obj.likes.filter(user=user).exists()

    def get_is_saved(self, obj):
        user = self._user()
        if not user or not user.is_authenticated:
            return False
        return obj.saves.filter(user=user).exists()

    def get_images(self, obj):
        post_images = obj.images.all()
        if post_images.exists():
            return [{'id': img.id, 'image_url': img.image_url, 'order': img.order}
                    for img in post_images]
        if obj.image_url:
            return [{'id': None, 'image_url': obj.image_url, 'order': 0}]
        return []


class CreatePostSerializer(serializers.ModelSerializer):
    image_urls = serializers.ListField(
        child=serializers.URLField(), write_only=True, required=False)

    class Meta:
        model  = Post
        fields = ['id', 'caption', 'location', 'destination', 'image_urls']

    def create(self, validated_data):
        image_urls = validated_data.pop('image_urls', [])
        post       = Post.objects.create(**validated_data)
        for i, url in enumerate(image_urls):
            PostImage.objects.create(post=post, image_url=url, order=i)
        return post