from core.responses import TrendifyResponse

from django.contrib.auth import authenticate

from rest_framework import status
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken


class LoginAPIView(APIView):
    '''
    Simple login view that returns access and refresh tokens

    Payload: {
        "email": "string",
        "password": "string"
    }

    Response: {
        "access_token": "string",
        "refresh_token": "string"
    }
    '''

    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if not email or not password:
                return TrendifyResponse.error(
                    error='Please provide both email and password', 
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            
            user = authenticate(username=email, password=password)

            if not user:
                return TrendifyResponse.error(
                    error='Invalid credentials',
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            
            refresh_token = RefreshToken.for_user(user)

            return TrendifyResponse.success(
                data={
                    'access_token': str(refresh_token.access_token),
                    'refresh_token': str(refresh_token),
                },
                message='Login successful!',
                status_code=status.HTTP_200_OK,
            )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

