import re
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

# Test connection between React and Django
@api_view(['GET'])
def test_connection(request):
    return Response({"message": "Django and React are connected!"})

# Sign_up
@api_view(['POST'])
def sign_up(request):
    print(request.data)
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    # Required check
    if not username or not email or not password:
        return Response({'detail': 'All fields are required.'}, status=400)

    # Username: Alphanumeric only
    if not re.fullmatch(r'^[a-zA-Z0-9]+$', username):
        return Response({'username': ['Username must be letters and numbers only.']}, status=400)

    # Email: Valid format
    try:
        validate_email(email)
    except ValidationError:
        return Response({'email': ['Enter a valid email address.']}, status=400)
    
    # Password: Min length
    if len(password) < 8:
        return Response({'password': ['Password must be at least 8 characters long.']}, status=400)

    # Password: must contain at least one uppercase, lowercase, number, and special character
    if not re.search(r'[A-Z]', password):
        return Response({'password': ['Password must include at least one uppercase letter.']}, status=400)
    if not re.search(r'[a-z]', password):
        return Response({'password': ['Password must include at least one lowercase letter.']}, status=400)
    if not re.search(r'[0-9]', password):
        return Response({'password': ['Password must include at least one number.']}, status=400)
    if not re.search(r'[^A-Za-z0-9]', password):
        return Response({'password': ['Password must include at least one special character.']}, status=400)

    # Check if username or email is taken
    if User.objects.filter(username=username).exists():
        return Response({'username': ['Username already exists.']}, status=400)

    if User.objects.filter(email=email).exists():
        return Response({'email': ['This email is already in use.']}, status=400)

    # Create user (auto-hashes password)
    user = User.objects.create_user(username=username, email=email, password=password)
    print(user)
    return Response({'message': 'User created successfully'}, status=201)

# Sign_in
@api_view(['POST'])
def sign_in(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'detail': 'Email and password are required.'}, status=400)

    try:
        user_obj = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'detail': 'Invalid credentials.'}, status=401)

    # Authenticate using the username (since Django needs it)
    user = authenticate(request, username=user_obj.username, password=password)

    if user:
        return Response({'message': 'Login successful', 'user_id': user.id})
    else:
        return Response({'detail': 'Invalid credentials.'}, status=401)
