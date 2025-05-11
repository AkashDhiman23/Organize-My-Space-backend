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

from .models import Admin, Member, EmailOTP
from .serializers import (
    AdminRegistrationSerializer,
    AdminCompanySerializer,
    MemberSerializer
)

### Step 1: Admin registers (name/email/password)
@api_view(['POST'])
def signup(request):
    serializer = AdminRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        admin = serializer.save()
        return Response({'admin_id': admin.AdminID}, status=201)
    return Response(serializer.errors, status=400)


### Step 2: Admin adds company details
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_company(request):
    admin = request.user  # the logged-in user
    serializer = AdminCompanySerializer(admin, data=request.data, partial=True)  # allow partial update
    if serializer.is_valid():
        serializer.save()
        return Response({'detail': 'Company details saved'}, status=200)
    return Response(serializer.errors, status=400)


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


### Admin creates new Member accounts (with role)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_member(request):
    admin = request.user
    if not isinstance(admin, Admin):
        return Response({'error': 'Only admins can create members'}, status=403)

    full_name = request.data.get('full_name')
    email     = request.data.get('email')
    role      = request.data.get('role', 'Designer')  # Default to 'Designer'
    
    # generate random password
    raw_pw    = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    member = Member(admin=admin, full_name=full_name, email=email, role=role)
    member.set_password(raw_pw)
    member.save()

    # Email credentials to the new member
    send_mail(
        'Your Member Account',
        f'Your login: {email}\nPassword: {raw_pw}\nRole: {role}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=True,
    )

    return Response(MemberSerializer(member).data, status=201)

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

