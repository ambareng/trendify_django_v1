import secrets
import string
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Create your models here.

class TrendifyUser(AbstractUser):
    email = models.EmailField(unique=True)
    
    # Make email the primary identifier
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def get_valid_password_reset_otp(self):
        """
        Get the latest PasswordResetOTP that is not expired and not used.
        Returns None if no valid OTP is found.
        """
        try:
            return self.password_reset_otps.filter(
                is_used=False,
                expired_at__gt=timezone.now()
            ).latest('created_at')
        except PasswordResetOTP.DoesNotExist:
            return None
    
    def __str__(self):
        return self.email


class PasswordResetOTP(models.Model):
    '''
    Model to store password reset otp data
    '''
    user = models.ForeignKey(TrendifyUser, on_delete=models.CASCADE, editable=False, related_name='password_reset_otps')
    otp = models.CharField(max_length=6, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    expired_at = models.DateTimeField(editable=False)
    is_used = models.BooleanField(default=False)
    # maybe make a field here that will store if already expired?

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['otp', 'is_used']),
            models.Index(fields=['user', 'is_used'])
        ]

    # why use class method and what is cls used for?
    @classmethod
    def generate_otp(cls, user):
        # why use secrets and string instead of random?
        otp = ''.join(secrets.choice(string.digits) for _ in range(6))
        # should we not auto set expired at 5 minutes from created_at if possible
        expired_at = timezone.now() + timezone.timedelta(minutes=5)

        otp = cls.objects.create(
            user=user,
            otp=otp,
            expired_at=expired_at,
        )

        return otp
    
    def is_expired(self):
        return timezone.now() >= self.expired_at
    
    def mark_as_used(self):
        self.is_used = True
        self.save()

    def __str__(self):
        return f"{self.user.email} - {self.otp}"
