from django.urls import path

from authentication.views import LoginAPIView

urlpatterns = [
    path('v1/login/', LoginAPIView.as_view(), name='login-v1'),
]