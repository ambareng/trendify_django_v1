from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from authentication.models import TrendifyUser


# Reusable validator functions
def validate_user_exists(email):
    """
    Validate that a user with the given email exists
    Raises ValidationError if user does not exist
    """
    if not TrendifyUser.objects.filter(email=email).exists():
        raise serializers.ValidationError("User does not exist")
    return email


def validate_otp_for_user(email, otp):
    """
    Validate OTP for a given user email
    Raises ValidationError if OTP is invalid or expired
    """
    user = TrendifyUser.objects.get(email=email)
    user_otp = user.get_valid_password_reset_otp()

    if not user_otp:
        raise serializers.ValidationError({"otp": "Invalid otp"})

    if user_otp.otp != otp:
        raise serializers.ValidationError({"otp": "Invalid otp"})
    
    return True


def validate_and_refresh_expired_otp(email, otp):
    """
    Validate OTP for a given user email with auto-refresh for expired OTPs
    
    If the OTP is correct but expired, automatically generates a new OTP
    and raises a ValidationError informing the user.
    
    Raises ValidationError if:
    - OTP is incorrect
    - OTP is correct but expired (after generating new OTP)
    """
    from authentication.models import PasswordResetOTP
    
    user = TrendifyUser.objects.get(email=email)
    
    # Get the most recent OTP (regardless of expiry or used status)
    try:
        latest_otp = user.password_reset_otps.filter(is_used=False).latest('created_at')
    except PasswordResetOTP.DoesNotExist:
        raise serializers.ValidationError({"otp": "Invalid otp"})
    
    # Check if OTP matches
    if latest_otp.otp != otp:
        raise serializers.ValidationError({"otp": "Invalid otp"})
    
    if latest_otp.is_expired():
        # OTP is correct but expired - generate a new one
        new_otp = PasswordResetOTP.generate_otp(user)
        raise serializers.ValidationError({
            "otp": f"OTP has expired. A new OTP has been generated sent to your email"
        })
    
    # OTP is valid
    return True


def validate_passwords_match(password_field, confirm_field, password_label="password"):
    """
    Factory function to create a validator that checks if two password fields match
    """
    def validator(data):
        if data.get(password_field) != data.get(confirm_field):
            raise serializers.ValidationError({
                confirm_field: f"{password_label.capitalize()} and confirm {password_label} do not match"
            })
        return data
    return validator


def validate_and_resend_otp(email, min_interval_seconds=60):
    """
    Validate and resend OTP for a user with throttling
    
    - If valid OTP exists and enough time has passed: Update last_sent_at and return existing OTP
    - If valid OTP exists but not enough time: Raise ValidationError with wait time
    - If no valid OTP exists: Generate new OTP
    
    Args:
        email: User email
        min_interval_seconds: Minimum seconds between resend attempts (default: 60)
    
    Returns:
        PasswordResetOTP: The OTP instance (existing or new)
    """
    from authentication.models import PasswordResetOTP
    
    user = TrendifyUser.objects.get(email=email)
    existing_otp = user.get_valid_password_reset_otp()
    
    if existing_otp:
        # Check if enough time has passed since last send
        if not existing_otp.can_resend(min_interval_seconds):
            from django.utils import timezone
            time_elapsed = (timezone.now() - existing_otp.last_sent_at).total_seconds()
            wait_time = min_interval_seconds - time_elapsed
            raise serializers.ValidationError(
                f"Please wait {int(wait_time)} seconds before requesting another OTP"
            )
        
        # Update last_sent_at and return existing OTP
        existing_otp.update_last_sent_at()
        return existing_otp
    else:
        # No valid OTP exists, generate new one
        from authentication.models import PasswordResetOTP
        return PasswordResetOTP.generate_otp(user)


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
        validate_passwords_match('password', 'confirm_password')(data)
        
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

    def validate_email(self, value):
        return validate_user_exists(value)


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer for OTP verification
    """
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, trim_whitespace=False)

    def validate_email(self, value):
        return validate_user_exists(value)

    def validate(self, data):
        validate_otp_for_user(data['email'], data['otp'])
        return data


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

    def validate_email(self, value):
        return validate_user_exists(value)

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
        Check that new_password and confirm_new_password match and validate OTP
        Uses auto-refresh for expired OTPs to improve UX
        """
        # Validate password match
        validate_passwords_match('new_password', 'confirm_new_password', 'new password')(data)
        
        # Validate OTP with auto-refresh if expired
        validate_and_refresh_expired_otp(data['email'], data['otp'])
        
        return data


class ResendOTPSerializer(serializers.Serializer):
    """
    Serializer for resending OTP to user email with throttling
    
    - Resends existing valid OTP if at least 1 minute has passed
    - Generates new OTP if no valid OTP exists
    - Enforces 1-minute cooldown between resend attempts
    """
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        return validate_user_exists(value)
    
    def validate(self, data):
        """
        Validate and handle OTP resend with throttling logic
        """
        # This will either return existing OTP (with updated last_sent_at) or generate new one
        # Will raise ValidationError if trying to resend too soon
        validate_and_resend_otp(data['email'], min_interval_seconds=60)
        
        return data