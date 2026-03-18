from django.urls import path
from . import views

urlpatterns = [
    # ── Auth & Profile ────────────────────────────────────────────────────────
    path('signup/',                          views.signup),
    path('login/',                           views.login_view),
    path('profile/',                         views.user_profile),
    path('profile/<int:user_id>/',           views.other_user_profile),
    path('follow/<int:user_id>/',            views.follow_user),

    # ── Followers / Following ─────────────────────────────────────────────────
    path('profile/<int:user_id>/followers/', views.get_followers),
    path('profile/<int:user_id>/following/', views.get_following),

    # ── Email OTP ─────────────────────────────────────────────────────────────
    path('otp/send/',                        views.send_otp),
    path('otp/verify/',                      views.verify_otp),

    # ── Trip Creation Flow ────────────────────────────────────────────────────
    path('savetrip/trip/',                   views.save_trip),
    path('savetrip/route/',                  views.save_route),
    path('savetrip/payment/',                views.save_payment),
    path('savetrip/contact/',                views.save_contact),

    # ── Trip Retrieval & Interaction ──────────────────────────────────────────
    path('savetrip/my-trips/',               views.get_user_trips),
    path('trips/search/',                    views.search_trips),
    path('trips/<int:trip_id>/detail/',      views.get_trip_detail),
    path('trips/join/confirm/',              views.confirm_join),
    path('trips/completed/',                 views.get_completed_trips),

    # ── Trip Cancel ───────────────────────────────────────────────────────────
    path('trips/<int:trip_id>/cancel/',      views.cancel_trip),

    # ── Trip Boarding OTP ─────────────────────────────────────────────────────
    path('trips/<int:trip_id>/start/',                views.start_trip),
    path('trips/<int:trip_id>/boarding/',             views.get_boarding_otps),
    path('trips/<int:trip_id>/my-otp/',               views.get_my_boarding_otp),
    path('trips/<int:trip_id>/verify/<int:user_id>/', views.verify_member_boarding),

    # ── Group ─────────────────────────────────────────────────────────────────
    path('groups/<int:group_id>/',           views.get_group_details),
    path('groups/<int:group_id>/rename/',    views.rename_group),

    # ── Posts ─────────────────────────────────────────────────────────────────
    path('posts/create/',                    views.create_post),
    path('posts/saved/',                     views.get_saved_posts),
    path('posts/<int:post_id>/',             views.delete_post, name='delete_post'),
    path('posts/<int:post_id>/like/',        views.toggle_like),
    path('posts/<int:post_id>/save/',        views.toggle_save),

    # ── Feed ──────────────────────────────────────────────────────────────────
    path('feed/',                            views.get_feed),
    path('search/record/',                   views.record_search),

    # ── Notifications ─────────────────────────────────────────────────────────
    path('notifications/',                            views.get_notifications),
    path('notifications/unread-count/',               views.get_unread_count),
    path('notifications/read-all/',                   views.mark_all_notifications_read),
    path('notifications/read/<int:notif_id>/',        views.mark_notification_read),
]