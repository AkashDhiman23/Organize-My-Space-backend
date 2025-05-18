import random, string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import random
import json
from django.contrib.auth import logout
from django.shortcuts import redirect

from .models import Admin, Member, EmailOTP
from .serializers import (
    AdminFullRegistrationSerializer,
    MemberSerializer
)

@api_view(['POST'])
def register_admin_full(request):
    serializer = AdminFullRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        admin = serializer.save()
        return Response({
            'message': 'Admin registered with company details!',
            'admin_id': admin.AdminID  
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


### Login endpoint for Admin & Member
@api_view(['POST'])
def login(request):
    email    = request.data.get('email')
    password = request.data.get('password')
    role     = request.data.get('role', 'admin')  # 'admin' or 'member'

    if role == 'admin':
        try:
            admin = Admin.objects.get(email=email)
            if admin.check_password(password):
                token = RefreshToken.for_user(admin)
                token['role'] = 'admin'
                return Response({
                    'refresh': str(token),
                    'access' : str(token.access_token)
                })
        except Admin.DoesNotExist:
            pass

    else:  # member login
        try:
            member = Member.objects.get(email=email)
            if member.check_password(password):
                token = RefreshToken.for_user(member)
                token['role'] = 'member'
                return Response({
                    'refresh': str(token),
                    'access' : str(token.access_token)
                })
        except Member.DoesNotExist:
            pass

    return Response({'error': 'Invalid credentials'}, status=401)



def logout_view(request):
    logout(request)
    return redirect('login')

### Admin creates new Member accounts (with role)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_member(request):
    full_name = request.data.get('full_name')
    email = request.data.get('email')
    role = request.data.get('role')
    password = request.data.get('password')

    # Check required fields
    if not all([full_name, email, role, password]):
        return Response({'error': 'All fields are required.'}, status=400)

    # Check for existing email
    if Member.objects.filter(email=email).exists():
        return Response({'error': 'Email already exists.'}, status=400)

    # Get admin (assuming request.user is an Admin or linked to Admin)
    try:
        admin = Admin.objects.get(user=request.user)
    except Admin.DoesNotExist:
        return Response({'error': 'Admin not found.'}, status=403)

    # Create Member
    member = Member(
        full_name=full_name,
        email=email,
        role=role,
        admin=admin
    )
    member.set_password(password)
    member.save()

    return Response({'message': 'Member created successfully.'}, status=201)

@csrf_exempt
def send_otp(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")
        otp = str(random.randint(100000, 999999))

        EmailOTP.objects.create(email=email, otp=otp)

        send_mail(
            'Your OTP Code',
            f'Your OTP is {otp}. It expires in 5 minutes.',
            'your_email@gmail.com',  # From email
            [email],
            fail_silently=False,
        )

        return JsonResponse({"message": "OTP sent to email."}, status=200)
    return JsonResponse({"error": "Only POST allowed"}, status=405)


@csrf_exempt
def verify_otp(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")
        otp = data.get("otp")

        try:
            otp_record = EmailOTP.objects.filter(email=email, otp=otp).latest('created_at')
            if otp_record.is_expired():
                return JsonResponse({"error": "OTP expired"}, status=400)
            otp_record.delete()  # Optional: delete once verified
            return JsonResponse({"message": "OTP verified"}, status=200)
        except EmailOTP.DoesNotExist:
            return JsonResponse({"error": "Invalid OTP"}, status=400)
    return JsonResponse({"error": "Only POST allowed"}, status=405)



@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def company_details(request):
    try:
        admin = Admin.objects.get(user=request.user)
    except Admin.DoesNotExist:
        return Response({'error': 'Admin not found.'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        return Response({
            'company_name': admin.company_name,
            'address': admin.address,
            'gst_details': admin.gst_details,
        })

    if request.method == 'PATCH':
        data = request.data
        admin.company_name = data.get('company_name', admin.company_name)
        admin.address = data.get('address', admin.address)
        admin.gst_details = data.get('gst_details', admin.gst_details)
        admin.save()
        return Response({'message': 'Company details updated.'})