from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import NotFound, ValidationError
from authentication.models import PasswordResetOTP, TrendifyUser
from authentication.serializers import ChangePasswordSerializer, ForgotPasswordSerializer, LoginSerializer, RefreshAccessTokenSerializer, RegisterSerializer, ResendOTPSerializer, VerifyAccessTokenSerializer, VerifyOTPSerializer
from core.responses import TrendifyResponse

from django.contrib.auth import authenticate

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

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
        "refresh_token": "string",
        "user": {
            "user_id": int,
            "email": string
        }
    }
    '''

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid()
        serializer.is_valid(raise_exception=True)
        
        user = authenticate(
            username=serializer.validated_data['email'], 
            password=serializer.validated_data['password'],
        )
        if not user:
            raise ValidationError('Invalid credentials')
        
        refresh_token = RefreshToken.for_user(user)
        return TrendifyResponse.success(
            data={
                'access_token': str(refresh_token.access_token),
                'refresh_token': str(refresh_token),
                'user': {
                    'id': user.id,
                    'email': user.email,
                }
            },
            message='Login successful!',
            status_code=status.HTTP_200_OK,
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
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = VerifyAccessTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
    
        email = serializer.validated_data['email']
        auth_header = request.headers.get('Authorization')
        access_token = auth_header.replace('Bearer', '', 1).strip()
         
        try:
            TrendifyUser.objects.get(email=email)
        except TrendifyUser.DoesNotExist:
            raise NotFound('User not found')
        
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
        serializer = RefreshAccessTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        refresh_token = serializer.validated_data['refresh_token']
        
        try:
            refresh = RefreshToken(refresh_token)

            return TrendifyResponse.success(
                data={
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh)
                },
                status_code=status.HTTP_200_OK,
            )
        except TokenError as e:
            raise ValidationError('Invalid token')


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
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
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


class ForgotPasswordAPIView(APIView):
    '''
    API Endpoint to send a reset password to a valid user email

    Payload: {
        email: string
    }

    Response: bool 
    '''

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        
        user = TrendifyUser.objects.get(email=email)
        otp = PasswordResetOTP.generate_otp(user)

        # TODO[ambareng] send actual email to user with otp here
        # TODO[ambareng] maybe also throttle this API Endpoint?
        
        return TrendifyResponse.success(
            data={
                'last_sent_at': otp.last_sent_at,
            },
            message='Reset password email sent'
        )


class VerifyOTPAPIView(APIView):
    '''
    API Endpoint to verify if otp is valid and not yet expired

    Payload: {
        'email': string,
        'otp': string
    }

    Response: bool
    '''

    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return TrendifyResponse.success(
            data=True,
            status_code=status.HTTP_200_OK,
        )


class ChangePasswordAPIView(APIView):
    '''
    API Endpoint to change password

    Payload: {
        'email': string,
        'otp': string,
        'new_password': string,
        'confirm_new_password': string,
    }

    Response: bool
    '''

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        new_password = serializer.validated_data['new_password']

        user = TrendifyUser.objects.get(email=email)
        user_otp = user.get_valid_password_reset_otp()
        
        user.set_password(new_password)
        user.save()
        user_otp.mark_as_used()
        
        return TrendifyResponse.success(
            data=True,
            message='Password changed successfully',
            status_code=status.HTTP_200_OK,
        )

class ResendOTPAPIView(APIView):
    '''
    API Endpoint to resend OTP to user email

    Payload: {
        'email': string
    }

    Response: bool
    '''

    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = TrendifyUser.objects.get(email=email)
        user_otp = user.get_valid_password_reset_otp()
        
        # TODO[ambareng] send actual email to user with otp here
        
        return TrendifyResponse.success(
            data={
                'last_sent_at': user_otp.last_sent_at,
            },
            message='OTP resent successfully',
            status_code=status.HTTP_200_OK,
        )
