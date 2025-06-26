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
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from .models import Customer, Member , Enquiry

from rest_framework.response import Response
from functools import wraps

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.contrib.auth import login as django_login
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt

from .models import Customer

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
        
        try:
            admin = Admin.objects.get(pk=admin_id)
        except Admin.DoesNotExist:
            return Response({'error': 'Unauthorized'}, status=401)

        # Attach the admin to the request for later use
        request.admin = admin
        return view_func(request, *args, **kwargs)

    return wrapped


@api_view(['POST'])
@permission_classes([AllowAny])
def register_admin_full(request):
    email = request.data.get('email', '').strip().lower()
    otp = request.data.get('otp', '').strip()

    cached_otp = cache.get(cache_key(email))

    if not cached_otp or cached_otp != otp:
        return Response(
            {"non_field_errors": ["OTP expired or not found. Please request a new one."]},
            status=status.HTTP_400_BAD_REQUEST
        )

    serializer = AdminFullRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        admin = serializer.save()
        django_login(request, admin)
        csrf_token = get_token(request)
        cache.delete(cache_key(email))
        return Response({
            "message": "Admin registered and logged in!",
            "admin_id": admin.AdminID,
            "csrfToken": csrf_token,
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])  # No auth required to access this view
def login(request):
    data = request.data
    email = data.get('email')
    password = data.get('password')

    # Try Admin login first
    try:
        user = Admin.objects.get(email=email)
        if check_password(password, user.password):
            request.session['admin_id'] = user.AdminID

            # 🔍 Print session content for debugging
            print("Session after admin login:", dict(request.session))

            return Response({'message': 'Admin login successful', 'role': 'Admin'})
        else:
            return Response({'error': 'Invalid email or password'}, status=401)
    except Admin.DoesNotExist:
        pass

    # Try Member login with any role (Designer, Manager, Production)
    try:
        member = Member.objects.get(email=email)
        if member.check_password(password):
            if member.role == Member.DESIGNER:
                request.session['designer_id'] = member.member_id
            elif member.role == Member.MANAGER:
                request.session['manager_id'] = member.member_id
            elif member.role == Member.PRODUCTION:
                request.session['production_id'] = member.member_id

            # 🔍 Print session content for debugging
            print("Session after member login:", dict(request.session))

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
        


@api_view(["GET"])
def all_customers_view(request):
    """
    GET /accounts/all-customers/

    • If a designer is logged in (session["designer_id"]) → customers whose
      projects are assigned to that designer.
    • If a production user is logged in (session["production_id"]) → customers
      whose projects are assigned to that production user.
    """

    designer_id   = request.session.get("designer_id")
    production_id = request.session.get("production_id")

    # 1️⃣ Determine caller role & member
    if designer_id:
        member_role = Member.DESIGNER
        member_id   = designer_id
        filter_key  = "projectdetail__assigned_designer"
    elif production_id:
        member_role = Member.PRODUCTION
        member_id   = production_id
        filter_key  = "projectdetail__assigned_production"
    else:
        return Response(
            {"detail": "designer_id or production_id not found in session"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    member = get_object_or_404(Member, member_id=member_id, role=member_role)

    # 2️⃣ Get customers linked to that member
    customers_qs = (
        Customer.objects
        .filter(**{filter_key: member})
        .distinct()
        # optional performance tweaks
        .select_related("manager")
        .prefetch_related("projectdetail_set")
    )

    # 3️⃣ Serialize, letting serializer know the caller
    serializer = CustomerSerializer(
        customers_qs,
        many=True,
        context={
            "member": member,
            "role":   member_role,
        },
    )

    # 4️⃣ Debug print only in DEBUG mode
    if settings.DEBUG:
        import json, textwrap
        print(
            f"[Dashboard] {member_role} {member_id} → {customers_qs.count()} customers\n"
            + textwrap.indent(json.dumps(serializer.data, indent=2, default=str), "  ")
        )

    return Response(serializer.data, status=status.HTTP_200_OK)




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





from django.http import JsonResponse, Http404
def customer_detail(request, customer_id):
    try:
        customer = Customer.objects.get(pk=customer_id)
    except Customer.DoesNotExist:
        raise Http404("Customer not found")

   
    data = {
        "id": customer.id,
        "name": customer.name,
        "email": customer.email,
        "contact_number" :customer.contact_number,
       
    }
    return JsonResponse(data)

from rest_framework import status, permissions
from django.shortcuts import get_object_or_404
from .models import Customer, ProjectDetail, Drawing
from .serializers import ProjectDetailSerializer, DrawingSerializer
from rest_framework.parsers import MultiPartParser, FormParser , JSONParser

class ProjectDetailView(APIView):
    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def get(self, request, customer_id):
        customer = get_object_or_404(Customer, id=customer_id)
        project, _ = ProjectDetail.objects.get_or_create(customer=customer)
        serializer = ProjectDetailSerializer(project)
        return Response(serializer.data)

    def post(self, request, customer_id):
        # You can treat POST as create or partial update here
        return self.update_project(request, customer_id)

    def patch(self, request, customer_id):
        # Recommended for partial update
        return self.update_project(request, customer_id)

    def update_project(self, request, customer_id):
        customer = get_object_or_404(Customer, id=customer_id)
        project, _ = ProjectDetail.objects.get_or_create(customer=customer)

        serializer = ProjectDetailSerializer(project, data=request.data, partial=True)
        if serializer.is_valid():
            # Check drawings count before saving
            if project.drawings.count() < 2:
                return Response(
                    {"detail": "Please upload at least 2 drawings before saving project details."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DrawingUploadView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, customer_id):
        project = get_object_or_404(ProjectDetail, customer_id=customer_id)

        # ➊ get number from form‑data
        try:
            num = int(request.data.get("drawing_num", 0))
        except (TypeError, ValueError):
            return Response({"detail": "drawing_num missing/invalid"}, status=400)

        if not (1 <= num <= 4):
            return Response({"detail": "drawing_num must be 1‑4"}, status=400)

        if project.drawings.filter(drawing_num=num).exists():
            return Response({"detail": "That drawing number already exists"}, status=400)

        f = request.data.get("file")
        if not f:
            return Response({"detail": "file missing"}, status=400)

        Drawing.objects.create(project=project, drawing_num=num, file=f)
        return Response({"detail": "uploaded", "drawing_num": num}, status=201)
    

from rest_framework import status as drf_status

class SendToProductionView(APIView):
    def post(self, request, customer_id):
        try:
            # Get the latest project for the customer
            project = ProjectDetail.objects.filter(customer__id=customer_id).latest('created_at')
        except ProjectDetail.DoesNotExist:
            return Response(
                {"error": "Project not found for this customer"},
                status=drf_status.HTTP_404_NOT_FOUND
            )
        
        # Force status to "In Production" regardless of request data
        data = request.data.copy()  # copy to modify
        data['status'] = "In Production"
        
        serializer = ProjectDetailSerializer(project, data=data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=drf_status.HTTP_400_BAD_REQUEST)
        
        serializer.save()

        print("Project updated successfully. ID:", serializer.data.get("id"))

        return Response(
            {
                "success": True,
                "id": serializer.data.get("id"),
                "status": serializer.data.get("status")
            },
            status=drf_status.HTTP_200_OK
        )

from rest_framework.generics import ListAPIView   
from rest_framework.exceptions import NotFound


class DrawingListView(ListAPIView):
    serializer_class = DrawingSerializer

    def get_queryset(self):
        cid = self.kwargs["customer_id"]
        project = get_object_or_404(ProjectDetail, customer_id=cid)
        return project.drawings.order_by("drawing_num")

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["request"] = self.request                # so build_absolute_uri works
        return ctx
    


import random, string, datetime
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt   # because you already pass CSRF in JS
from django.utils.timezone import now


OTP_TTL = 300  # 5 minutes expiry

def generate_otp(length=6):
    return ''.join(str(random.randint(0,9)) for _ in range(length))

def cache_key(email):
    return f"signup_otp_{email.lower().strip()}"


@api_view(['POST'])
@permission_classes([AllowAny])
def send_signup_otp(request):
    try:
        email = json.loads(request.body).get("email", "").strip().lower()
    except Exception:
        return HttpResponseBadRequest("Invalid JSON")

    if not email:
        return HttpResponseBadRequest("Email required")

    otp = generate_otp()
    cache.set(cache_key(email), otp, timeout=OTP_TTL)

    
    send_mail(
    subject="Your One-Time Password for Organize My Space",
    message=(
        "Hello,\n\n"
        "Thank you for joining Organize My Space! To complete your signup, please use the following One-Time Password (OTP):\n\n"
        f"*** {otp} ***\n\n"
        "This OTP will expire in 5 minutes.\n\n"
        "If you did not request this, please ignore this email.\n\n"
        "Thanks,\n"
        "The Organize My Space Team"
    ),
    from_email="your-email@example.com",
    recipient_list=[email],
)

    return JsonResponse({"detail": "OTP sent"})





# MANAGER
# 
class AddCustomerWithProject(APIView):
    def post(self, request, *args, **kwargs):
        # ───────── 1. build & validate customer ─────────
        customer_payload = {
            "name":  request.data.get("name"),
            "email": request.data.get("email"),
            "contact_number": request.data.get("contact_number"),
            "address": request.data.get("address"),
            "progress_percentage": request.data.get("progress_percentage", 0),
        }

        # optional manager from session
        manager_id = request.session.get("manager_id")
        if manager_id:
            customer_payload["manager"] = get_object_or_404(Member, pk=manager_id).pk

        customer_ser = CustomerSerializer(data=customer_payload)
        if not customer_ser.is_valid():
            return Response(customer_ser.errors, status=status.HTTP_400_BAD_REQUEST)

        customer = customer_ser.save()        # <- row in Customer table

        # ───────── 2. build & validate project ─────────
        project_payload = {
            # do NOT include "customer" here because field is read‑only
            "product_name":  request.data.get("product_name", ""),
            "length_ft":     request.data.get("length_ft"),
            "width_ft":      request.data.get("width_ft"),
            "depth_in":      request.data.get("depth_in"),
            "body_color":    request.data.get("body_color", ""),
            "door_color":    request.data.get("door_color", ""),
            "body_material": request.data.get("body_material", ""),
            "door_material": request.data.get("door_material", ""),
            "deadline_date": request.data.get("deadline_date"),
            "status":        request.data.get("status", "Pending"),
        }

        project_ser = ProjectDetailSerializer(data=project_payload)
        if not project_ser.is_valid():
            customer.delete()                 # rollback
            return Response(project_ser.errors, status=status.HTTP_400_BAD_REQUEST)

        # 🔑 inject FK when saving
        project_ser.save(customer=customer)   # now customer_id is set

        return Response(
            {
                "message":  "Customer and Project created successfully.",
                "customer": customer_ser.data,
                "project":  project_ser.data,
            },
            status=status.HTTP_201_CREATED
        )
    

class ProjectListAPIView(APIView):
    """
    GET /accounts/projects-list/

    • Returns every ProjectDetail whose customer is managed by the
      logged‑in manager’s company (admin_id match).
    • Bundles the company’s Designers *and* Productions so the
      frontend can populate its two <select> menus.
    """

    def get(self, request):
        # 1️⃣ Identify calling manager
        manager_id = request.session.get("manager_id")
        if not manager_id:
            return Response({"error": "manager_id not found in session"}, status=400)

        manager = get_object_or_404(
            Member, member_id=manager_id, role=Member.MANAGER
        )
        company_admin_id = manager.admin_id

        # 2️⃣ Projects belonging to this company
        projects_qs = (
            ProjectDetail.objects
            .select_related(
                "customer",
                "customer__manager",
                "assigned_designer",
                "assigned_production",     # <‑‑ NEW
            )
            .filter(customer__manager__admin_id=company_admin_id)
        )

        projects_data = [
            {
                "id":                 p.id,
                "product_name":       p.product_name,
                "status":             p.status,
                "assigned_designer": (
                    p.assigned_designer.member_id if p.assigned_designer else None
                ),
                "assigned_production": (
                    p.assigned_production.member_id if p.assigned_production else None
                ),                                     # <‑‑ NEW
                "customer_name":      p.customer.name if p.customer else "N/A",
                "customer":           p.customer.id   if p.customer else None,
            }
            for p in projects_qs
        ]

        # 3️⃣ Designers and Productions from the same company
        company_members = Member.objects.filter(admin_id=company_admin_id)

        designers_data = [
            {"id": m.member_id, "full_name": m.full_name}
            for m in company_members if m.role == Member.DESIGNER
        ]

        productions_data = [
            {"id": m.member_id, "full_name": m.full_name}
            for m in company_members if m.role == Member.PRODUCTION
        ]

        # 4️⃣ Ship to client
        return Response(
            {
                "projects":    projects_data,
                "designers":   designers_data,
                "productions": productions_data,   # <‑‑ NEW
            },
            status=status.HTTP_200_OK,
        )

class AssignDesignerView(APIView):
    def patch(self, request, project_id):
        designer_id = request.data.get("assigned_designer")
        if not designer_id:
            return Response({"error": "Designer ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        project = get_object_or_404(ProjectDetail, pk=project_id)
        designer = get_object_or_404(Member, pk=designer_id, role__icontains="designer")

        project.assigned_designer = designer

        # ✅ Update status
        if project.assigned_production:
            project.status = "In Design"
        else:
            project.status = "Assigned"

        project.save()

        return Response({"message": "Designer assigned successfully."}, status=status.HTTP_200_OK)

class AssignProductionView(APIView):
    def patch(self, request, project_id):
        production_id = request.data.get("assigned_production")
        project = get_object_or_404(ProjectDetail, pk=project_id)

        if production_id in ("", None):
            # Unassign production
            project.assigned_production = None

            # Optionally downgrade status
            if project.assigned_designer:
                project.status = "Assigned"
            else:
                project.status = "Pending"

            project.save()
            return Response(
                {"message": "Production assignment cleared."},
                status=status.HTTP_200_OK,
            )

        production_member = get_object_or_404(Member, pk=production_id, role__icontains="production")

        project.assigned_production = production_member

        # ✅ Update status
        if project.assigned_designer:
            project.status = "In Design"
        else:
            project.status = "Assigned"  # Optional fallback

        project.save()

        return Response(
            {"message": "Production assigned successfully."},
            status=status.HTTP_200_OK,
        )

class TeamMembersAPIView(APIView):
    """
    GET /accounts/team-members/
    → All colleagues (Designer + Production) who share the same company (admin)
      as the logged‑in Manager.  Assumes 'manager_id' lives in the session.
    """

    # Roles we care about
    _TARGET_ROLES = (Member.DESIGNER, Member.PRODUCTION)

    def get(self, request):
        # ── 1. who is calling? ───────────────────────────────────────────────
        manager_id = request.session.get("manager_id")
        print(f"[DEBUG] manager_id from session → {manager_id}")

        if not manager_id:
            return Response(
                {"error": "manager_id not found in session"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Logged‑in *manager* row (raises 404 if id invalid or not a Manager)
        manager = get_object_or_404(Member, member_id=manager_id, role=Member.MANAGER)
        company_admin_id = manager.admin_id
        print(f"[DEBUG] company admin_id of manager → {company_admin_id}")

        # ── 2. colleagues in same company, limited to Designer / Production ──
        colleagues_qs = Member.objects.filter(
            admin_id=company_admin_id,
            role__in=self._TARGET_ROLES,
        )

        # extra ?role=<Designer|Production> filter if the client wants
        role_param = request.GET.get("role")
        if role_param:
            colleagues_qs = colleagues_qs.filter(role__iexact=role_param)

        # ── 3. verbose debug print so you SEE what is returned ───────────────
        if not colleagues_qs.exists():
            print("[DEBUG] No colleagues found matching criteria.")
        for c in colleagues_qs:
            print(
                f"[DEBUG] Colleague id={c.member_id:<3} | "
                f"name={c.full_name:<20} | role={c.role:<11} | "
                f"admin_id={c.admin_id}"
            )

        # ── 4. ship to client ────────────────────────────────────────────────
        serializer = MemberSerializer(colleagues_qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    




@api_view(["GET"])
def member_profile_view(request):
  member_id = (
        request.session.get("manager_id")
        or request.session.get("designer_id")
        or request.session.get("production_id")
    )
  if not member_id:
        return Response({"error": "No member ID found in session."},
                        status=status.HTTP_400_BAD_REQUEST)

  member = get_object_or_404(Member, member_id=member_id)
  admin  = member.admin   # FK to Admin

  payload = {
        "member": {
            "member_id": member.member_id,
            "full_name": member.full_name,
            "email":     member.email,
            "role":      member.role,
            "created_at": member.created_at,
        },
        "company": {
            "AdminID":      admin.AdminID,
            "company_name": admin.company_name,
            "address":      admin.address,
            "gst_details":  admin.gst_details,
            "company_logo": admin.company_logo.url if admin.company_logo else None ,
        }
    }
  return Response(payload, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def logout(request):
    """
    Remove any role key that might be present, then flush the session.
    """
    for key in ('admin_id', 'designer_id', 'manager_id', 'production_id'):
        request.session.pop(key, None)

    # Rotate session ID, clears data, prevents reuse
    request.session.flush()

    return Response({'message': 'Logout successful'})





from .models      import Customer, ProjectDetail, ProductionImage
from .serializers import ProductionImageSerializer
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, parser_classes
from django.db.models import Max

@api_view(["GET", "POST"])

@parser_classes([MultiPartParser, FormParser])   # so DRF will read multipart
def production_images_view(request, customer_id):
    """
    GET  -> list production images for the latest project of <customer_id>
    POST -> upload one or more images (multipart "file")
            adds them as ProductionImage(image_num=1..4)

    Front‑end can POST files individually or several at once.
    """
    # 1️⃣  find the customer’s newest project
    customer = get_object_or_404(Customer, pk=customer_id)
    try:
        project = (
            ProjectDetail.objects
            .filter(customer=customer)
            .latest("created_at")
        )
    except ProjectDetail.DoesNotExist:
        return Response(
            {"error": "No project found for this customer."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # ── GET ──────────────────────────────────────────────────────────────
    if request.method == "GET":
        imgs = project.production_images.all().order_by("image_num")
        serializer = ProductionImageSerializer(
            imgs, many=True, context={"request": request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    # ── POST ─────────────────────────────────────────────────────────────
    files = request.FILES.getlist("file")
    if not files:
        return Response(
            {"error": "No file part named 'file' found."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # current highest image_num
    current_max = (
        project.production_images.aggregate(max_num=Max("image_num"))["max_num"]
        or 0
    )

    if current_max >= 4:
        return Response(
            {"error": "Maximum of 4 production images reached."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    created_objs = []
    next_num = current_max + 1

    for up in files:
        if next_num > 4:
            break  # ignore extras
        obj = ProductionImage.objects.create(
            project=project,
            image_num=next_num,
            file=up,
        )
        created_objs.append(obj)
        next_num += 1

    serializer = ProductionImageSerializer(
        created_objs, many=True, context={"request": request}
    )
    return Response(serializer.data, status=status.HTTP_201_CREATED)





class SendToManagerView(APIView):
    """
    POST /accounts/projects/customer/<customer_id>/send-to-manager/

    • Finds the latest ProjectDetail for the given customer.
    • Forces its status to **Completed** (adjust if you prefer “Assigned”).
    • Returns {success: true, id, status}.
    """

    def post(self, request, customer_id):
        # 1️⃣  latest project for this customer
        try:
            project = (
                ProjectDetail.objects.filter(customer__id=customer_id)
                .latest("created_at")
            )
        except ProjectDetail.DoesNotExist:
            return Response(
                {"error": "Project not found for this customer"},
                status=drf_status.HTTP_404_NOT_FOUND,
            )

        # 2️⃣  always set status → Completed
        data = request.data.copy()
        data["status"] = "Completed"   # or "Assigned" if you’d rather

        # 3️⃣  partial update
        serializer = ProjectDetailSerializer(project, data=data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=drf_status.HTTP_400_BAD_REQUEST)

        serializer.save()

        print("Project updated successfully. ID:", serializer.data.get("id"))

        return Response(
            {
                "success": True,
                "id":     serializer.data.get("id"),
                "status": serializer.data.get("status"),
            },
            status=drf_status.HTTP_200_OK,
        )
    
@api_view(["GET"])
def all_customers_admin_view(request):
    admin_id = request.session.get("admin_id")
    if not admin_id:
        return Response({"detail": "admin_id not found in session"}, status=400)

    # Retrieve admin instance
    admin = get_object_or_404(Admin, pk=admin_id)

    # Filter customers whose manager belongs to this admin
    customers = Customer.objects.filter(manager__admin=admin)

    # No extra context needed now
    serializer = CustomerSerializer(customers, many=True)
    return Response(serializer.data)


@api_view(['GET', 'PUT'])
@admin_session_required
def admin_settings_view(request):
    admin_id = request.session.get("admin_id")
    if not admin_id:
        return Response({"detail": "Admin not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

    admin = get_object_or_404(Admin, pk=admin_id)

    if request.method == 'GET':
        serializer = AdminFullRegistrationSerializer(admin, context={'request': request})
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = AdminFullRegistrationSerializer(admin, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def enquiry_list_create(request):
    if request.method == 'GET':
        enquiries = Enquiry.objects.all().order_by('-submitted_at')
        data = []
        for enquiry in enquiries:
            data.append({
                'id': enquiry.id,
                'name': enquiry.name,
                'email': enquiry.email,
                'enquiry_text': enquiry.enquiry_text,
                'submitted_at': enquiry.submitted_at,
            })
        return Response(data)

    elif request.method == 'POST':
        name = request.data.get('name')
        email = request.data.get('email')
        enquiry_text = request.data.get('enquiry_text')

        if not all([name, email, enquiry_text]):
            return Response(
                {"detail": "Name, email and enquiry_text are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        enquiry = Enquiry.objects.create(
            name=name,
            email=email,
            enquiry_text=enquiry_text
        )

        # Prepare email content using a simple HTML template string
        subject = "Thank you for contacting Us- Organize My Space!"
        from_email = "your-email@example.com"
        to_email = [email]

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color:#f9f9f9; padding:20px;">
          <div style="max-width:600px; margin:auto; background:#ffffff; border-radius:8px; padding:30px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            <h2 style="color:#4a90e2;">Thank You for Reaching Out, {name}!</h2>
            <p style="font-size:16px; color:#333;">
              We appreciate you contacting us. Your enquiry is important and we'll respond as soon as possible.
            </p>
            <hr style="margin: 20px 0; border:none; border-top:1px solid #ddd;" />
            <h3 style="color:#4a90e2;">Your Submitted Enquiry:</h3>
            <p style="background:#f1f1f1; padding:15px; border-radius:5px; font-size:15px; color:#555;">{enquiry_text}</p>
            <p style="font-size:14px; color:#777;">
              If you need immediate assistance, please reply to this email or call our support line.
            </p>
            <p style="margin-top:30px; font-size:14px; color:#aaa;">Best regards,<br>Organize My Space Team</p>
          </div>
        </body>
        </html>
        """

        text_content = strip_tags(html_content)  # fallback for email clients that don't support HTML

        email_message = EmailMultiAlternatives(subject, text_content, from_email, to_email)
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()

        return Response({
            'id': enquiry.id,
            'name': enquiry.name,
            'email': enquiry.email,
            'enquiry_text': enquiry.enquiry_text,
            'submitted_at': enquiry.submitted_at,
            'detail': 'Enquiry received and confirmation email sent.'
        }, status=status.HTTP_201_CREATED)