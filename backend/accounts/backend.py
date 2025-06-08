from django.contrib.auth.backends import BaseBackend
from .models import Admin

class EmailBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = Admin.objects.get(email=email)
            if user.check_password(password):
                return user
        except Admin.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return Admin.objects.get(pk=user_id)
        except Admin.DoesNotExist:
            return None
