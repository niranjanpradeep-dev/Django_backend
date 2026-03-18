from django.db import models
from django.contrib.auth.models import User


class UserDetails(models.Model):
    user             = models.OneToOneField(User, on_delete=models.CASCADE, related_name='details')
    supabase_uid     = models.CharField(max_length=128, unique=True)
    name             = models.CharField(max_length=255)
    email            = models.EmailField(unique=True)
    phone            = models.CharField(max_length=15, blank=True, null=True)
    bio              = models.TextField(blank=True, default='')
    profile_picture  = models.TextField(blank=True, null=True)
    trips_registered = models.JSONField(default=list, blank=True)
    trips_success    = models.JSONField(default=list, blank=True)
    created_at       = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_details'

    def __str__(self):
        return self.name


class Trip(models.Model):
    STATUS_CHOICES = [
        ('upcoming',  'Upcoming'),
        ('ongoing',   'Ongoing'),
        ('completed', 'Completed'),
    ]
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    destination = models.CharField(max_length=255)
    start_date  = models.DateField()
    end_date    = models.DateField()
    vehicle     = models.CharField(max_length=50)
    passengers  = models.IntegerField()
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='upcoming')
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'trip_details'


class Route(models.Model):
    trip           = models.OneToOneField(Trip, on_delete=models.CASCADE)
    start_location = models.CharField(max_length=255)
    stops          = models.JSONField(default=list)
    start_datetime = models.DateTimeField(null=True, blank=True)
    end_datetime   = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'route_details'


class Vehicle(models.Model):
    trip           = models.OneToOneField(Trip, on_delete=models.CASCADE, related_name='vehicle_details')
    vehicle_number = models.CharField(max_length=20)
    vehicle_model  = models.CharField(max_length=100)

    class Meta:
        db_table = 'vehicle_details'


class PaymentDetails(models.Model):
    trip             = models.OneToOneField(Trip, on_delete=models.CASCADE, related_name='payment_info')
    price_per_head   = models.IntegerField()
    booking_deadline = models.DateTimeField()
    cancel_deadline  = models.DateTimeField()
    PAYMENT_CHOICES  = [('UPI', 'UPI'), ('Bank', 'Bank Transfer')]
    payment_method   = models.CharField(max_length=10, choices=PAYMENT_CHOICES)
    upi_id           = models.CharField(max_length=100, null=True, blank=True)
    account_no       = models.CharField(max_length=50,  null=True, blank=True)
    ifsc             = models.CharField(max_length=20,  null=True, blank=True)

    class Meta:
        db_table = 'payment_details'


class ContactDetails(models.Model):
    trip              = models.OneToOneField(Trip, on_delete=models.CASCADE, related_name='contact_info')
    phone             = models.CharField(max_length=15)
    email             = models.EmailField()
    is_phone_verified = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    created_at        = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'contact_details'


class GroupDetails(models.Model):
    trip          = models.OneToOneField(Trip, on_delete=models.CASCADE, related_name='group_info')
    group_name    = models.CharField(max_length=255)
    admin         = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_groups')
    members_count = models.IntegerField(default=1)
    members_list  = models.JSONField(default=list)
    created_at    = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'group_details'


class SeatAvailability(models.Model):
    trip            = models.OneToOneField(Trip, on_delete=models.CASCADE, related_name='seat_info')
    total_seats     = models.IntegerField()
    available_seats = models.IntegerField()

    class Meta:
        db_table = 'remaining_seats'


class Post(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    trip        = models.ForeignKey(Trip, on_delete=models.CASCADE, related_name='posts',
                                    null=True, blank=True)
    image_url   = models.TextField()
    caption     = models.TextField(blank=True, default='')
    location    = models.CharField(max_length=255, blank=True)
    destination = models.CharField(max_length=100, blank=True)
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'posts'
        ordering = ['-created_at']

    def __str__(self):
        return f"Post by {self.user.username}"


class PostImage(models.Model):
    post      = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='images')
    image_url = models.URLField()
    order     = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order']


class PostLike(models.Model):
    user       = models.ForeignKey(User, on_delete=models.CASCADE, related_name='liked_posts')
    post       = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'post')


class PostSave(models.Model):
    user       = models.ForeignKey(User, on_delete=models.CASCADE, related_name='saved_posts')
    post       = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='saves')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'post')


class UserSearchHistory(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='search_history')
    destination = models.CharField(max_length=100)
    searched_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-searched_at']


class Follower(models.Model):
    follower   = models.ForeignKey(User, on_delete=models.CASCADE, related_name='following')
    following  = models.ForeignKey(User, on_delete=models.CASCADE, related_name='followers')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table        = 'followers'
        unique_together = ('follower', 'following')

    def __str__(self):
        return f"{self.follower.username} → {self.following.username}"


class CompletedTrip(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    trip        = models.ForeignKey(Trip, on_delete=models.CASCADE)
    destination = models.CharField(max_length=255)
    start_date  = models.DateField()
    end_date    = models.DateField()
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'completed_trips'

    def __str__(self):
        return f"{self.user.username} - {self.destination}"


class BoardingOTP(models.Model):
    trip       = models.ForeignKey(Trip, on_delete=models.CASCADE, related_name='boarding_otps')
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    otp        = models.CharField(max_length=4)
    verified   = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table        = 'boarding_otps'
        unique_together = ('trip', 'user')

    def __str__(self):
        return f"OTP {self.otp} for {self.user.username} on trip {self.trip.id}"


class AppNotification(models.Model):
    """
    In-app notification record.
    verb values used in this app:
      'liked your post'        — actor liked recipient's post
      'started following you'  — actor followed recipient
      'joined your trip'       — actor joined recipient (admin)'s trip
      'started the trip'       — self-notification for admin: go scan OTPs
      'your trip has started'  — member: trip is ongoing, show your OTP
      'posted in your trip'    — actor posted in a trip recipient belongs to
      'cancelled the trip'     — admin cancelled; recipient is a member
      'left the trip'          — member left; recipient is admin
    """
    recipient      = models.ForeignKey(User, on_delete=models.CASCADE,
                                        related_name='notifications')
    actor          = models.ForeignKey(User, on_delete=models.CASCADE,
                                        related_name='sent_notifications')
    verb           = models.CharField(max_length=100)
    target_type    = models.CharField(max_length=20, blank=True, null=True)  # 'trip' | 'post'
    target_id      = models.IntegerField(null=True, blank=True)
    target_details = models.JSONField(default=dict, blank=True)
    read           = models.BooleanField(default=False)
    created_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'app_notifications'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.actor} → {self.recipient}: {self.verb}"