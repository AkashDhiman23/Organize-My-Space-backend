from rest_framework import serializers
from .models import Admin, Member

class AdminFullRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['email', 'full_name', 'password', 'company_name', 'address', 'gst_details']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        admin = Admin(**validated_data)
        admin.set_password(password)  # hashes the password properly
        admin.save()
        return admin
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = Admin.objects.create_user(password=password, **validated_data)
        return user


class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['member_id', 'full_name', 'email', 'role']
