import re
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout as django_logout
from django.middleware.csrf import get_token
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings

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

    # Username: Alphanumeric only + maximum 50 characters
    if not re.fullmatch(r'[a-zA-Z0-9 ]{1,50}', username) or username.strip() == '':
        return Response({
            'username': [
                'Username must be 1-50 characters, letters, numbers, and spaces only. Cannot be only spaces.'
            ]
        }, status=400)

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
        login(request, user)
        return Response({'message': 'Login successful', 'user_id': user.id})
    else:
        return Response({'detail': 'Invalid credentials.'}, status=401)

# Get user's logged in status and info
@api_view(['GET'])
def get_logged_in_user(request):
    if request.user.is_authenticated:
        return Response({
            'isAuthenticated': True,
            'user_id': request.user.id,
            'email': request.user.email,
            'username': request.user.username,
        })
    else:
        return Response({'isAuthenticated': False}, status=200)

# Get the token before making a post request
@api_view(['GET'])
def get_csrf_token(request):
    token = get_token(request)
    return Response({'csrfToken': token})

# Logout
@api_view(['POST'])
def sign_out(request):
    django_logout(request)
    return Response({'message': 'Logged out successfully'})

# Forgot password
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = user.pk
            reset_link = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
            send_mail(
                subject="Reset Your Password",
                message=f"Click the link to reset your password:\n{reset_link}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )
            return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

# Reset Password
class ResetPasswordConfirmView(APIView):
    def post(self, request):
        uid = request.data.get("uid")
        token = request.data.get("token")
        password = request.data.get("password")

        try:
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({"message": "Password has been reset successfully."})
            else:
                return Response({"error": "Invalid or expired token."}, status=400)
        except User.DoesNotExist:
            return Response({"error": "Invalid user."}, status=400)
