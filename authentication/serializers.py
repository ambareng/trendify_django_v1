from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from authentication.models import TrendifyUser


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, trim_whitespace=False)


class VerifyAccessTokenSerializer(serializers.Serializer):
    """
    Serializer for access token verification
    """
    email = serializers.EmailField(required=True)


class RefreshAccessTokenSerializer(serializers.Serializer):
    """
    Serializer for refreshing access token
    """
    refresh_token = serializers.CharField(required=True, trim_whitespace=False)


class RegisterSerializer(serializers.Serializer):
    """
    Serializer for user registration with password validation
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True, 
        trim_whitespace=False,
        write_only=True
    )
    confirm_password = serializers.CharField(
        required=True, 
        trim_whitespace=False,
        write_only=True
    )

    def validate_password(self, value):
        """
        Validate password complexity using Django's password validators
        """
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, data):
        # validate that passwords match
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({
                "confirm_password": "Password and confirm password do not match"
            })
        
        # validate that user still does not exist
        if TrendifyUser.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({
                "email": "User already exists"
            })
        
        return data


class ForgotPasswordSerializer(serializers.Serializer):
    """
    Serializer for forgot password request
    """
    email = serializers.EmailField(required=True)


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer for OTP verification
    """
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, trim_whitespace=False)


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing password with OTP
    """
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, trim_whitespace=False)
    new_password = serializers.CharField(
        required=True, 
        trim_whitespace=False,
        write_only=True
    )
    confirm_new_password = serializers.CharField(
        required=True, 
        trim_whitespace=False,
        write_only=True
    )

    def validate_new_password(self, value):
        """
        Validate new password complexity using Django's password validators
        """
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, data):
        """
        Check that new_password and confirm_new_password match
        """
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError({
                "confirm_new_password": "New password and confirm new password do not match"
            })
        return data
