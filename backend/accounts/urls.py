from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import login, get_csrf_token
from .views import csrf_token_view
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import user_info
from .views import delete_customer
from .views import customers_view
from .views import customers_view_admin
from .views import  members_view 

from . import views
from .views import ProjectDetailView, DrawingUploadView

from .views import SendToProductionView

from .views import (
   
    DrawingListView, 
    ProjectListAPIView,
    AssignDesignerView,
    TeamMembersAPIView,
    member_profile_view,
     AssignProductionView,
     production_images_view,
     SendToManagerView,
     all_customers_admin_view,
     admin_settings_view,
     enquiry_list_create,
  
)

from .views import AddCustomerWithProject

urlpatterns = [
    
      path('enquiries/', enquiry_list_create, name='enquiry-list-create'),
    

      # Universal logout 
    path('logout/', views.logout, name='logout'),
    




 # Project assignment + retrieval
    path('projects-list/', ProjectListAPIView.as_view(), name='project-list'),
    path('projects-assign/<int:project_id>/', AssignDesignerView.as_view(), name='assign-designer'),


     path("projects-assign-production/<int:project_id>/", AssignProductionView.as_view(), name="assign-production"),

    # Team members (used to populate dropdown for designer assignment)
    path('team-members/', TeamMembersAPIView.as_view(), name='team-members'),
  path('add-customer-project/', AddCustomerWithProject.as_view(), name='add-customer-project'),
    

      path("projects/customer/<int:customer_id>/send-to-production/",
     SendToProductionView.as_view(),
     name="send_to_production_by_customer"),


       path("send-otp/",    views.send_signup_otp,    name="send-signup-otp"),

    
      path("customers/<int:customer_id>/project/", ProjectDetailView.as_view(), name="project-detail"),
    path("customers/<int:customer_id>/project/drawing/", DrawingUploadView.as_view(), name="drawing-upload"),

    path('signup/', views.register_admin_full, name='register_admin_full'),
    path('login/', views.login, name='login'),
    path('create-member/', views.create_member, name='create-member'),
    path('csrf/', get_csrf_token, name='get_csrf_token'),
    path('company-details/', views.get_company_details, name='company-details'),
    
    path('csrf-token/', csrf_token_view, name='csrf-token'),


    path("member-profile/", member_profile_view, name="member-profile"),



     path(
        "customers/<int:customer_id>/project/drawings/",  # <- plural!
        DrawingListView.as_view(),
        name="drawing-list",
    ),

     path('customers/<int:customer_id>/', views.customer_detail, name='customer-detail'),
    
    path('all-customers/', views.all_customers_view, name='all_customers'),


     path('customers/<int:pk>/', delete_customer, name='delete_customer'),
      path("customers/", customers_view, name="customers"),


      path("members/",        members_view,  name="members"),

      path("customers_admin/", customers_view_admin, name="customers_admon"),

    
    

      path('api/user/', user_info, name='user_info'),


      path(
        "customers/<int:customer_id>/project/production-images/",
        production_images_view,
        name="production-images",
    ),

      path(
        "projects/customer/<int:customer_id>/send-to-manager/",
        SendToManagerView.as_view(),
        name="send_to_manager_by_customer",
    ),


      
    
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),   # Login: get tokens
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh token
    path('customers/<int:customer_id>/', views.customer_detail, name='customer-detail'),



    path('all_customers_admin/', all_customers_admin_view, name='all_customers_admin'),



       path('admin_settings/', admin_settings_view, name='admin_settings'),

    
]

