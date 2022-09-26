from django.urls import path
from .views import UserProfileView, RegisterView, SendPasswordResetEmailView, UserChangePasswordView, PasswordResetView, \
    SendVerifyEmailView, VerifyEmailView, LogoutView, LogoutAllView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('profile/', UserProfileView.as_view()),
    path('change-password/', UserChangePasswordView.as_view()),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view()),
    path('reset-password/<uid>/<token>/', PasswordResetView.as_view()),
    path('send-verify-email/', SendVerifyEmailView.as_view()),
    path('verify-email/<uid>/<token>/', VerifyEmailView.as_view()),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('logout_all/', LogoutAllView.as_view(), name='auth_logout_all'),
]