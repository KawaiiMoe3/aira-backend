import re
from rest_framework import serializers
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from .models import Profile

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = '__all__'

    def validate_full_name(self, value):
        if len(value) > 50 or not re.match(r'^[A-Za-z0-9 ]+$', value):
            raise serializers.ValidationError("Full name must be alphanumeric, spaces only, max 50 characters.")
        return value

    def validate_phone(self, value):
        # Malaysian mobile number: 01X-XXXXXXX or 01X-XXXXXXXX
        if not re.match(r'^01[0-46-9]-?[0-9]{7,8}$', value):
            raise serializers.ValidationError("Please enter a valid Malaysian mobile number.")
        return value

    def validate(self, attrs):
        url_fields = ['linkedin', 'github', 'portfolio', 'other_link']
        validator = URLValidator()
        for field in url_fields:
            url = attrs.get(field)
            if url:
                try:
                    validator(url)
                except ValidationError:
                    raise serializers.ValidationError({field: "Enter a valid URL."})
        return attrs
