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
from .views import (
    ProjectDetailCreateView,
    ProjectDetailRetrieveUpdateView,
)
from .views import ProjectDrawingUploadView
from . import views



urlpatterns = [
    
      # create (only if not yet created)
    path(
    "customers/<int:customer_id>/project/create/",
    ProjectDetailCreateView.as_view(),
    name="projectdetail-create",
),
path(
    "customers/<int:customer_id>/project/",
    ProjectDetailRetrieveUpdateView.as_view(),
    name="projectdetail-rud",
),

    path('signup/', views.register_admin_full, name='register_admin_full'),
    path('login/', views.login, name='login'),
    path('create-member/', views.create_member, name='create-member'),
    path('csrf/', get_csrf_token, name='get_csrf_token'),
    path('company-details/', views.get_company_details, name='company-details'),
    path('logout/', views.logout_view, name='logout'),
    path('csrf-token/', csrf_token_view, name='csrf-token'),



     path('customers/<int:customer_id>/', views.customer_detail, name='customer-detail'),
    
    path('all-customers/', views.all_customers_view, name='all_customers'),


     path('customers/<int:pk>/', delete_customer, name='delete_customer'),
      path("customers/", customers_view, name="customers"),


      path("members/",        members_view,  name="members"),

      path("customers_admin/", customers_view_admin, name="customers_admon"),

    
    

      path('api/user/', user_info, name='user_info'),

      
    
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),   # Login: get tokens
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh token


     path(
        "customers/<int:customer_id>/project/drawing/",
        ProjectDrawingUploadView.as_view(),
        name="projectdrawing-upload",
    ),
]
