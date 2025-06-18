from functools import cache
from rest_framework import serializers
from .models import Admin, Member,Customer , ProjectDetail
from .models import Drawing
from django.core.cache import cache



class AdminFullRegistrationSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(write_only=True)

    class Meta:
        model = Admin
        fields = ['AdminID', 'email', 'full_name', 'password', 'company_name', 'address', 'gst_details', 'otp']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data.pop('otp', None)  # remove otp from user creation
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
        model = ProjectDetail
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
            "status",          # added status here
            "drawings_count",
        ]
        read_only_fields = ("customer",)


class DrawingSerializer(serializers.ModelSerializer):
    file = serializers.SerializerMethodField()
    image_url = serializers.SerializerMethodField()

    class Meta:
        model  = Drawing
        fields = ("id", "drawing_num", "file", "image_url", "uploaded_at")

    # helpers
    def _abs(self, url):
        request = self.context.get("request")
        return request.build_absolute_uri(url) if request else url

    def get_file(self, obj):
        return self._abs(obj.file.url) if obj.file else None

    def get_image_url(self, obj):
        # optional preview image if you store one
        return self._abs(obj.image_url.url) if getattr(obj, "image_url", None) else None