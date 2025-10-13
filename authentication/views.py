from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import NotFound, ValidationError
from authentication.models import PasswordResetOTP, TrendifyUser
from authentication.serializers import LoginSerializer, RefreshAccessTokenSerializer, RegisterSerializer, VerifyAccessTokenSerializer
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
            return TrendifyResponse.error(
                error='Invalid credentials',
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        
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
        try:
            email = request.data.get('email')

            if not email:
                return TrendifyResponse.error(
                    error='Please provide email',
                )
            
            try:
                user = TrendifyUser.objects.get(email=email)
                otp = user.get_valid_password_reset_otp()

                if not otp:
                    otp = PasswordResetOTP.generate_otp(user)
            except TrendifyUser.DoesNotExist:
                return TrendifyResponse.error(
                    error='Invalid email',
                )

            # TODO[ambareng] send actual email to user with otp here
            # TODO[ambareng] maybe also throttle this API Endpoint?
            
            return TrendifyResponse.success(
                data={
                    'expired_at': otp.expired_at,
                },
                message='Reset password email sent'
            )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        try:
            email = request.data.get('email')
            otp = request.data.get('otp')

            if not email or not otp:
                return TrendifyResponse.error(
                    error='Please provide email and otp'
                )
            
            try:
                user = TrendifyUser.objects.get(email=email)
                user_otp = user.get_valid_password_reset_otp()

                if not user_otp:
                    return TrendifyResponse.error(
                        error='Invalid otp',
                    )
            except TrendifyUser.DoesNotExist:
                return TrendifyResponse.error(
                    error='Invalid email',
                )
            
            if user_otp.otp != otp:
                return TrendifyResponse.error(
                    error='Invalid otp',
                )
            
            return TrendifyResponse.success(
                data=True,
                status_code=status.HTTP_200_OK,
            )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        try:
            email = request.data.get('email')
            otp = request.data.get('otp')
            new_password = request.data.get('new_password')
            confirm_new_password = request.data.get('confirm_new_password')


            if not email or not otp or not new_password or not confirm_new_password:
                return TrendifyResponse.error(
                    error='Please provide email, otp, new password and confirm new password',
                )
            
            if new_password != confirm_new_password:
                return TrendifyResponse.error(
                    error='New password and confirm new password do not match',
                )
            
            try:
                user = TrendifyUser.objects.get(email=email)
                user_otp = user.get_valid_password_reset_otp()

                if not user_otp:
                    return TrendifyResponse.error(
                        error='Invalid otp',
                    )
                if user_otp.otp != otp:
                    return TrendifyResponse.error(
                        error='Invalid otp',
                    )
            except TrendifyUser.DoesNotExist:
                return TrendifyResponse.error(
                    error='Invalid email',
                )
            
            user.set_password(new_password)
            user.save()

            user_otp.mark_as_used()
            
            return TrendifyResponse.success(
                data=True,
                message='Password changed successfully',
                status_code=status.HTTP_200_OK,
            )
        except Exception as e:
            return TrendifyResponse.error(
                error=str(e),
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


