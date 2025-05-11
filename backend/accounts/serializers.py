from rest_framework import serializers
from .models import Admin, Member

class AdminRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['email', 'full_name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        return Admin.objects.create_user(**validated_data)


class AdminCompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['company_name', 'address', 'gst_details']


class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['member_id', 'full_name', 'email', 'role']
