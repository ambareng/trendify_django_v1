from django.contrib import admin
from django.utils import timezone

from .models import TrendifyUser, PasswordResetOTP


class ValidPasswordResetOTPInline(admin.TabularInline):
    model = PasswordResetOTP
    fields = ("otp", "created_at", "expired_at")
    readonly_fields = fields
    can_delete = False
    extra = 0

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.filter(is_used=False, expired_at__gt=timezone.now())


@admin.register(TrendifyUser)
class TrendifyUserAdmin(admin.ModelAdmin):
    inlines = [ValidPasswordResetOTPInline]



