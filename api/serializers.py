import re
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import Users

class UserSerializer(serializers.ModelSerializer):
    # Ensure registered email is unique
    email = serializers.EmailField(
        validators=[UniqueValidator(queryset=Users.objects.all(), message="Email already exists.")]
    )
    
    class Meta:
        model = Users
        fields = '__all__'
    
    def validate_username(self, value):
        if not value:
            raise serializers.ValidationError("Username is required.")
        if not re.match(r'^[A-Za-z0-9]{1,20}$', value):
            raise serializers.ValidationError("Username must be alphanumeric and not more than 20 characters.")
        return value

    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required.")
        return value

    def validate_password(self, value):
        if not value:
            raise serializers.ValidationError("Password is required.")
        if len(value) < 6 or \
           not re.search(r'[A-Z]', value) or \
           not re.search(r'[a-z]', value) or \
           not re.search(r'[0-9]', value) or \
           not re.search(r'[@#$%^&+=!]', value):
            raise serializers.ValidationError(
                "Password must be at least 6 characters and include uppercase, lowercase, number, and special char."
            )
        return value
