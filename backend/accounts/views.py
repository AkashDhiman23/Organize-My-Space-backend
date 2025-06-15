import json
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, login as auth_login, logout
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import login as django_login
from django.middleware.csrf import get_token

from .models import Customer, Member

from rest_framework.response import Response
from functools import wraps

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.contrib.auth import login as auth_login
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login

from django.contrib.auth import login as django_login
from django.contrib.auth.hashers import check_password


from .models import Admin, Member
from .serializers import (
    AdminFullRegistrationSerializer,
    MemberSerializer,
    CustomerSerializer,
)


from rest_framework.response import Response
from functools import wraps


def admin_session_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        admin_id = request.session.get('admin_id')
        if not admin_id:
            return Response({'error': 'Unauthorized'}, status=401)
        request.admin_id = admin_id  # lowercase here
        return view_func(request, *args, **kwargs)
    return wrapped

# -------------------------
# Admin Registration - Public
# -------------------------
@api_view(['POST'])
@permission_classes([AllowAny])
def register_admin_full(request):
    serializer = AdminFullRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        admin = serializer.save()

        # Log user in (create session)
        django_login(request, admin)

        # Get CSRF token to send in response
        csrf_token = get_token(request)

        return Response({
            'message': 'Admin registered and logged in!',
            'admin_id': admin.AdminID,
            'csrfToken': csrf_token,
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def login(request):
    data = request.data
    email = data.get('email')
    password = data.get('password')

    # Try Admin login first
    try:
        user = Admin.objects.get(email=email)
        if check_password(password, user.password):
            request.session['admin_id'] = user.AdminID
            return Response({'message': 'Admin login successful', 'role': 'Admin'})
        else:
            return Response({'error': 'Invalid email or password'}, status=401)
    except Admin.DoesNotExist:
        pass

    # Try Member login with any role (Designer, Manager, Production)
    try:
        member = Member.objects.get(email=email)
        if member.check_password(password):
            # Save member id to session based on role
            if member.role == Member.DESIGNER:
                request.session['designer_id'] = member.member_id
            elif member.role == Member.MANAGER:
                request.session['manager_id'] = member.member_id
            elif member.role == Member.PRODUCTION:
                request.session['production_id'] = member.member_id

            return Response({'message': f'{member.role} login successful', 'role': member.role})
        else:
            return Response({'error': 'Invalid email or password'}, status=401)
    except Member.DoesNotExist:
        return Response({'error': 'Invalid email or password'}, status=401)



from .models import Customer, Member
from .serializers import CustomerSerializer



@csrf_exempt
@api_view(['GET', 'POST'])
def customers_view(request):
    manager_id = request.session.get('manager_id')
    print(f"Manager ID from session: {manager_id}")

    if not manager_id:
        return Response({'error': 'Only logged-in Managers can access'}, status=status.HTTP_403_FORBIDDEN)

    try:
        manager = Member.objects.get(member_id=manager_id, role=Member.MANAGER)
    except Member.DoesNotExist:
        return Response({'error': 'Invalid manager session'}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        customers = Customer.objects.filter(manager=manager)
        serializer = CustomerSerializer(customers, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        data = request.data.copy()
        data['manager'] = manager.member_id
        data['admin'] = manager.admin.AdminID if manager.admin else None

        serializer = CustomerSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print("Serializer errors:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        



@api_view(['GET'])
def all_customers_view(request):
    customers = Customer.objects.all()
    serializer = CustomerSerializer(customers, many=True)
    print(f"All Customers: {serializer.data}")  
    return Response(serializer.data)
# -------------------------
# Logout View
# -------------------------
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    logout(request)
    return Response({'message': 'Logged out successfully.'})

# -------------------------
# Admin creates Member accounts - Protected
# -------------------------

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST

from rest_framework.authentication import BasicAuthentication

@api_view(['POST'])
@admin_session_required
def create_member(request):
    try:
        admin_id = request.session.get('admin_id')
        if not admin_id:
            return Response({'error': 'Admin not authenticated.'}, status=status.HTTP_403_FORBIDDEN)

        admin = Admin.objects.get(AdminID=admin_id)

        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        data['admin'] = admin.AdminID  # Optional if you set it inside create()

        serializer = MemberSerializer(data=data, context={'admin': admin})
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Member created successfully.',
                'member': serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Admin.DoesNotExist:
        return Response({'error': 'Admin not found.'}, status=status.HTTP_404_NOT_FOUND)



@api_view(['GET'])
@admin_session_required
def get_company_details(request):
    try:
        
        admin = Admin.objects.get(AdminID=request.admin_id)
        
        # Build members list
        members = admin.members.all()  # thanks to related_name='members' in Member model
        members_data = [
            {
                'full_name': m.full_name,
                'email': m.email,
                'role': m.role,
            }
            for m in members
        ]

        return Response({
            'admin_id': admin.AdminID,
            'full_name': admin.full_name,
            'email': admin.email,
            'company_name': admin.company_name,
            'address': admin.address,
            'gst_number': admin.gst_details,
            'members': members_data,
        })
    except Admin.DoesNotExist:
        return Response({'error': 'Admin not found'}, status=404)

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required


@api_view(['DELETE'])
def delete_customer(request, pk):
    try:
        customer = Customer.objects.get(pk=pk)
    except Customer.DoesNotExist:
        return Response({'error': 'Customer not found'}, status=status.HTTP_404_NOT_FOUND)

    note = request.data.get('note', '').strip()
    if not note:
        return Response({'error': 'Deletion note is required.'}, status=status.HTTP_400_BAD_REQUEST)

    user = request.user
    user_info = user.email if hasattr(user, 'email') else 'AnonymousUser'
    print(f"User {user_info} deleted customer {customer.name} with note: {note}")

    customer.delete()
    return Response({'message': 'Customer deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user_info(request):
    user = request.user
    return Response({
        "username": user.username,
        "email": user.email,
    })






@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user(request):
    user = request.user
    return Response({
        'id': user.AdminID,
        'username': user.username,
        'email': user.email,
    })

@api_view(["GET"])
@admin_session_required
def members_view(request):
    admin_id = request.session.get("admin_id")
    try:
        admin = Admin.objects.get(AdminID=admin_id)
    except Admin.DoesNotExist:
        return Response({"error": "Admin not found."},
                        status=status.HTTP_404_NOT_FOUND)

    members = (Member.objects
               .filter(admin=admin)
               .exclude(email__iexact=admin.email)
               .order_by("-member_id"))         

    return Response(MemberSerializer(members, many=True).data,
                    status=status.HTTP_200_OK)

# -------------------------
# CSRF token endpoint
# -------------------------

from django.views.decorators.http import require_GET

@require_GET
@ensure_csrf_cookie
def get_csrf_token(request):
    # This sets the CSRF cookie in the browser
    return JsonResponse({'detail': 'CSRF cookie set'})


@require_GET
@ensure_csrf_cookie
def csrf_token_view(request):
    return JsonResponse({'message': 'CSRF token set'})


@api_view(["GET"])
@admin_session_required
def customers_view_admin(request):
    """
    Return all customers that belong to the logged‑in Admin.
    """
    admin_id = request.session.get("admin_id")
    try:
        admin = Admin.objects.get(AdminID=admin_id)
    except Admin.DoesNotExist:
        return Response({"error": "Admin not found."},
                        status=status.HTTP_404_NOT_FOUND)

    customers = (Customer.objects
                 .filter(admin=admin)
                 .select_related("manager")
                 .order_by("-id"))

    return Response(CustomerSerializer(customers, many=True).data,
                    status=status.HTTP_200_OK)


from rest_framework import generics, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import ProjectDetail
from .serializers import ProjectDetailSerializer
from accounts.models import Customer, Member

class ProjectDetailCreateView(generics.CreateAPIView):
    serializer_class   = ProjectDetailSerializer
  
    parser_classes     = (MultiPartParser, FormParser)

    def perform_create(self, serializer):
        customer_id   = self.kwargs["customer_id"]
        customer      = generics.get_object_or_404(Customer, pk=customer_id)
        designer_user = self.request.user

        # ---------- DEBUG LOG ----------
        # 👇 prints to console / gunicorn log
        print(
            f"[ProjectDetailCreate] customer #{customer.id}  "
            f"name={customer.name!r}  email={customer.email}"
        )
        # --------------------------------

        serializer.save(customer=customer, designer=designer_user)


class ProjectDetailRetrieveUpdateView(APIView):
   def get_object(self, customer_id):
    customer = get_object_or_404(Customer, id=customer_id)
    obj, created = ProjectDetail.objects.get_or_create(
        customer=customer,
        defaults={
            "length_ft": 0.00,
            "width_ft": 0.00,
            "depth_in": 0.00,
        }
    )
    return obj

from django.shortcuts import get_object_or_404
class ProjectDrawingUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, customer_id):
        # Validate customer exists
        customer = get_object_or_404(Customer, pk=customer_id)

        # Expect file in request.FILES['file']
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({"detail": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Retrieve or create ProjectDetail for customer
        project_detail, created = ProjectDetail.objects.get_or_create(customer=customer)

        # Assuming ProjectDetail model has a FileField named 'drawing_pdf' or similar
        project_detail.drawing_pdf.save(file_obj.name, file_obj, save=True)

        return Response({"detail": "Drawing uploaded successfully"}, status=status.HTTP_201_CREATED)


from django.http import JsonResponse, Http404
def customer_detail(request, customer_id):
    try:
        customer = Customer.objects.get(pk=customer_id)
    except Customer.DoesNotExist:
        raise Http404("Customer not found")

    # Example: return some customer details as JSON
    data = {
        "id": customer.id,
        "name": customer.name,
        "email": customer.email,
        # Add any other fields you want to expose
    }
    return JsonResponse(data)


from .models import Customer, ProjectDetail, ProjectDrawing
from .serializers import ProjectDrawingSerializer
class ProjectDrawingUploadView(generics.CreateAPIView):
    serializer_class = ProjectDrawingSerializer
   

    def post(self, request, customer_id, *args, **kwargs):
        # Verify customer exists
        customer = get_object_or_404(Customer, id=customer_id)
        
        # Retrieve the project linked to the customer
        # Assuming one project per customer or you want the first one
        try:
            project = ProjectDetail.objects.get(customer=customer)
        except ProjectDetail.DoesNotExist:
            return Response({"detail": "Project not found for this customer."}, status=status.HTTP_404_NOT_FOUND)

        # Prepare data for serializer
        data = request.data.copy()
        data['project'] = project.id  # link the drawing to the project

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)