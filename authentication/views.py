from django.contrib.auth.password_validation import validate_password
from django.forms import ValidationError
from authentication.models import TrendifyUser
from core.responses import TrendifyResponse

from django.contrib.auth import authenticate

from rest_framework import status
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken


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


class VerifyAccessTokenAPIView(APIView):
    '''
    APIView to verify if access token is valid/still not expired

    Payload: {
        'email': string,
        'access_token': string
    }

    Response: bool
    '''

    def post(self, request):
        try:
            email = request.data.get('email')
            access_token = request.data.get('access_token')

            if (email is None or access_token is None):
                return TrendifyResponse.error(
                    error='Please provide both email and access token',
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            
            user = TrendifyUser.objects.get(email=email)

            if (user is None):
                return TrendifyResponse.error(
                    error='User not found',
                    status_code=status.HTTP_404_NOT_FOUND,
                )
            
            try:
                AccessToken(access_token)
                return TrendifyResponse.success(
                    data=True,
                    status_code=status.HTTP_200_OK,
                )
            except Exception as e:
                return TrendifyResponse.success(
                    data=False,
                    status_code=status.HTTP_200_OK,
                )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RefreshAccessTokenAPIView(APIView):
    '''
    APIView to refresh access token

    Payload: {
        'refresh_token': string
    }

    Response: {
        'refresh_token': string,
        'access_token': string
    }
    '''

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return TrendifyResponse.error(
                error='Please provide refresh_token',
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        
        try:
            refresh = RefreshToken(refresh_token)

            return TrendifyResponse.success(
                data={
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh)
                },
                status_code=status.HTTP_200_OK,
            )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RegisterAPIView(APIView):
    '''
    API Endpoint to register a new user
    
    Payload: {
        'email': string,
        'password': string,
        'confirm_password': string
    }

    Response: bool
    '''

    def post(self, request):
        try:
            #  make request.data.get be serializer make sure if there is an error it still has same format as Trendify.error
            email = request.data.get('email')
            password = request.data.get('password')
            confirm_password = request.data.get('confirm_password')

            if (not email or not password or not confirm_password):
                return TrendifyResponse.error(
                    error='Please provide email, password and confirm password',
                )
            # make as well serializer and make password complex validation
            if (password != confirm_password):
                return TrendifyResponse.error(
                    error='Password and confirm password do not match',
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            
            if TrendifyUser.objects.filter(email=email).exists():
                return TrendifyResponse.error(
                    error='User already exists',
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            
            try:
                validate_password(password)
            except ValidationError as e:
                return TrendifyResponse.error(
                    error=f'Invalid password: {e}',
                )
            
            user = TrendifyUser.objects.create_user(
                email=email,
                username=email,
                password=password,
            )
            user.save()

            return TrendifyResponse.success(
                data=True,
                message='User registered successfully',
                status_code=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
