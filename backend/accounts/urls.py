from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('add-company/', views.add_company, name='add-company'),
    path('login/', views.login, name='login'),
    path('create-member/', views.create_member, name='create-member'),
     path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
]
