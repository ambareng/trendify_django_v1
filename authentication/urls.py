from django.urls import path

from authentication.views import LoginAPIView, VerifyAccessTokenAPIView

urlpatterns = [
    path('v1/login/', LoginAPIView.as_view(), name='login-v1'),
    path('v1/verify-access-token/', VerifyAccessTokenAPIView.as_view(), name='verify-access-token-v1'),
]