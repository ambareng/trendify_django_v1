from django.urls import path

from authentication.views import ChangePasswordAPIView, LoginAPIView, ResendOTPAPIView, VerifyAccessTokenAPIView, RefreshAccessTokenAPIView, \
    RegisterAPIView, ForgotPasswordAPIView, VerifyOTPAPIView

urlpatterns = [
    path('v1/login/', LoginAPIView.as_view(), name='login-v1'),
    path('v1/verify-access-token/', VerifyAccessTokenAPIView.as_view(), name='verify-access-token-v1'),
    path('v1/refresh-access-token/', RefreshAccessTokenAPIView.as_view(), name='refresh-access-token-v1'),
    path('v1/register/', RegisterAPIView.as_view(), name='register-v1'),
    path('v1/forgot-password/', ForgotPasswordAPIView.as_view(), name='forgot-password-v1'),
    path('v1/verify-otp/', VerifyOTPAPIView.as_view(), name='verify-otp-v1'),
    path('v1/change-password/', ChangePasswordAPIView.as_view(), name='change-password-v1'),
    path('v1/resend-otp/', ResendOTPAPIView.as_view(), name='resend-otp-v1'),
]