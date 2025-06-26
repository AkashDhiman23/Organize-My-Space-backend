from functools import cache
from rest_framework import serializers
from .models import Admin, Member,Customer , ProjectDetail ,ProductionImage
from .models import Drawing
from django.core.cache import cache



class AdminFullRegistrationSerializer(serializers.ModelSerializer):
    company_logo = serializers.SerializerMethodField()

    class Meta:
        model = Admin
        fields = [
            'AdminID', 'email', 'full_name', 'password',
            'company_name', 'address', 'gst_details', 'company_logo'
        ]
        extra_kwargs = {'password': {'write_only': True}}

    def get_company_logo(self, obj):
        request = self.context.get('request')
        if obj.company_logo:
            url = obj.company_logo.url
            if request:
                return request.build_absolute_uri(url)
            return url
        return None

    def update(self, instance, validated_data):
        request = self.context.get('request')
        company_logo = request.FILES.get('company_logo') if request else None

        if company_logo:
            instance.company_logo = company_logo

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance

    def create(self, validated_data):
        request = self.context.get('request')
        company_logo = request.FILES.get('company_logo') if request else None
        password = validated_data.pop('password')

        user = Admin.objects.create_user(password=password, **validated_data)

        if company_logo:
            user.company_logo = company_logo
            user.save()

        return user


class MemberSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    admin = serializers.PrimaryKeyRelatedField(read_only=True)  # admin set from view, not client
    
    # ➜ NEW: human‑readable admin block
    admin_info = AdminFullRegistrationSerializer(source='admin', read_only=True)


    class Meta:
        model = Member
        fields = ['member_id', 'admin','admin_info', 'full_name', 'email', 'password', 'role', 'created_at']
        read_only_fields = ['member_id', 'created_at', 'admin']

    def create(self, validated_data):
        password = validated_data.pop('password')
        admin = self.context['admin']  # pass admin from serializer context
        member = Member(admin=admin, **validated_data)
        member.set_password(password)
        member.save()
        return member
    

class CustomerSerializer(serializers.ModelSerializer):
    latest_project = serializers.SerializerMethodField()

    class Meta:
        model = Customer
        fields = [
            'id', 'manager', 'name', 'email', 'address', 'contact_number',
            'progress_percentage', 'created_at', 'updated_at', 'latest_project'
        ]

    def update(self, instance, validated_data):
        instance.progress_percentage = validated_data.get('progress_percentage', instance.progress_percentage)
        instance.manager = validated_data.get('manager', instance.manager)
        instance.save()
        return instance

    def get_latest_project(self, obj):
        # Return latest project for the customer regardless of who is assigned
        from .models import ProjectDetail  # avoid circular import
        from .serializers import ProjectDetailSerializer

        latest = (
            ProjectDetail.objects
            .filter(customer=obj)
            .order_by('-created_at')
            .first()
        )

        return ProjectDetailSerializer(latest).data if latest else None

    

class ProjectDetailSerializer(serializers.ModelSerializer):
    drawings_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = ProjectDetail
        fields = [
            "id",
            "customer",        # read-only field
            "product_name",    # added product_name
            "length_ft",
            "width_ft",
            "depth_in",

            "assigned_designer",
            "assigned_production",
           
            "body_color",
            "door_color",
            "body_material",
            "door_material",
            "deadline_date",   # added deadline_date
            "status",
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
    


class ProductionImageSerializer(serializers.ModelSerializer):
    file       = serializers.SerializerMethodField()
    image_url  = serializers.SerializerMethodField()

    class Meta:
        model  = ProductionImage
        fields = ("id", "image_num", "file", "image_url", "uploaded_at")

    # ── helpers (reuse _abs from DrawingSerializer) ─────────────────────
    def _abs(self, url):
        request = self.context.get("request")
        return request.build_absolute_uri(url) if request else url

    def get_file(self, obj):
        return self._abs(obj.file.url) if obj.file else None

    def get_image_url(self, obj):
        # optional preview thumb if you ever store one
        return (
            self._abs(obj.image_url.url)
            if getattr(obj, "image_url", None)
            else None
        )