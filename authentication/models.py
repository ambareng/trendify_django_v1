from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class TrendifyUser(AbstractUser):
    email = models.EmailField(unique=True)
    
    # Make email the primary identifier
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email
