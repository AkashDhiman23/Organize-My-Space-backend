from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.register_admin_full, name='register_admin_full'),
    path('login/', views.login, name='login'),
    path('create-member/', views.create_member, name='create-member'),
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('logout/', views.logout_view, name='logout'),
    path('company-details/', views.company_details, name='company-details')
]
