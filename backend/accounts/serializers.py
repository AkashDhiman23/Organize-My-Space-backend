from rest_framework import serializers
from .models import Admin, Member,Customer , ProjectDetail
from .models import ProjectDrawing



class AdminCompanyDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['AdminID', 'email', 'full_name', 'company_name', 'address', 'gst_details']

class AdminFullRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['AdminID', 'email', 'full_name', 'password', 'company_name', 'address', 'gst_details']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = Admin.objects.create_user(password=password, **validated_data)
        return user

class MemberSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    admin = serializers.PrimaryKeyRelatedField(read_only=True)  # admin set from view, not client

    class Meta:
        model = Member
        fields = ['member_id', 'admin', 'full_name', 'email', 'password', 'role', 'created_at']
        read_only_fields = ['member_id', 'created_at', 'admin']

    def create(self, validated_data):
        password = validated_data.pop('password')
        admin = self.context['admin']  # pass admin from serializer context
        member = Member(admin=admin, **validated_data)
        member.set_password(password)
        member.save()
        return member
    

class CustomerSerializer(serializers.ModelSerializer):
    # Show manager as ID
    class Meta:
        model = Customer
        fields = ['id', 'admin', 'manager', 'name', 'email', 'address', 'contact_number', 'progress_percentage', 'created_at', 'updated_at']

    def update(self, instance, validated_data):
        # Allow updating progress_percentage and manager only
        instance.progress_percentage = validated_data.get('progress_percentage', instance.progress_percentage)
        instance.manager = validated_data.get('manager', instance.manager)
        instance.save()
        return instance



class ProjectDetailSerializer(serializers.ModelSerializer):
    square_feet = serializers.ReadOnlyField()

    class Meta:
        model  = ProjectDetail
        fields = (
            "id",
            "customer",     
            "designer",      # auto‑set to logged‑in designer
            "length_ft",
            "width_ft",
            "depth_in",
            "square_feet",
            "drawing1",
            "drawing2",
            "drawing3",
            "drawing4",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "square_feet", "created_at", "updated_at", "designer")

    # -------- validation to enforce 2‑4 drawings --------
    def validate(self, attrs):
        files = [
            attrs.get("drawing1") or getattr(self.instance, "drawing1", None),
            attrs.get("drawing2") or getattr(self.instance, "drawing2", None),
            attrs.get("drawing3") or getattr(self.instance, "drawing3", None),
            attrs.get("drawing4") or getattr(self.instance, "drawing4", None),
        ]
        count = len([f for f in files if f])
        if count < 2:
            raise serializers.ValidationError("At least 2 drawings are required.")
        if count > 4:
            raise serializers.ValidationError("No more than 4 drawings allowed.")
        return attrs

class ProjectDrawingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectDrawing
        fields = ['id', 'project', 'drawing_file', 'uploaded_at']
        read_only_fields = ['id', 'uploaded_at']