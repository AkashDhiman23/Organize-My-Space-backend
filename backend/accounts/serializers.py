from rest_framework import serializers
from .models import Admin, Member,Customer , ProjectDetail
from .models import Drawing



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
    drawings_count = serializers.IntegerField(read_only=True)

    class Meta:
        model  = ProjectDetail
        fields = [
            "id",
            "customer",
            "length_ft",
            "width_ft",
            "depth_in",
            "material_name",
            "body_color",
            "door_color",
            "body_material",
            "door_material",
            "drawings_count",
        ]
        read_only_fields = ("customer",)


class DrawingSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Drawing
        fields = ("id", "project", "drawing_num", "file", "uploaded_at")
        read_only_fields = ("project", "drawing_num", "uploaded_at")