from django.contrib import admin
from .models import UserProfile, EmailVerificationToken, LoginAttempt, BannedIP

admin.site.register(UserProfile)
admin.site.register(EmailVerificationToken)
admin.site.register(LoginAttempt)
admin.site.register(BannedIP)