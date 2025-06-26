from django.contrib.auth.backends import BaseBackend
from .models import Admin

class ModelBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        print(f"Authenticate called with email={email}")
        try:
            user = Admin.objects.get(email=email)
            if user.check_password(password):
                print("Password matched")
               
                return user
            else:
                print("Password did NOT match")
        except Admin.DoesNotExist:
            print("User does not exist")
        return None