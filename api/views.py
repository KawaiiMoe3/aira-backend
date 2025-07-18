import re
import json
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout as django_logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.middleware.csrf import get_token
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.timezone import now
from django.conf import settings
from django.http import JsonResponse

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
@csrf_protect
def sign_out(request):
    print(">> Logout Request Received")
    print(">> Is Authenticated:", request.user.is_authenticated)
    print(">> sessionid cookie:", request.COOKIES.get("sessionid"))
    print(">> csrftoken cookie:", request.COOKIES.get("csrftoken"))
    
    django_logout(request)
    return Response({'message': 'Logged out successfully'})

# Forgot password
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except ValidationError:
            return Response({"error": "Please enter a valid email address."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = user.pk
            reset_link = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
            
            try:
                # Email content
                subject = "Reset Your Password"
                from_email = settings.DEFAULT_FROM_EMAIL
                to = [email]

                text_content = f"Click the link to reset your password:\n{reset_link}"
                html_content = render_to_string("emails/reset_password.html", {
                    "user": user,
                    "reset_link": reset_link,
                    "now": now(),
                })

                # Send email
                email_msg = EmailMultiAlternatives(subject, text_content, from_email, to)
                email_msg.attach_alternative(html_content, "text/html")
                email_msg.send()

            except Exception as e:
                return Response({"error": "Failed to send reset email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "We've sent you an email, please check your mailbox."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "The email was not found."}, status=status.HTTP_404_NOT_FOUND)

# Reset Password
class ResetPasswordConfirmView(APIView):
    def post(self, request):
        uid = request.data.get("uid")
        token = request.data.get("token")
        password = request.data.get("password")
        
         # Password validation
        def is_valid_password(pw):
            return (
                len(pw) >= 8
                and re.search(r"[A-Z]", pw)
                and re.search(r"[a-z]", pw)
                and re.search(r"[0-9]", pw)
                and re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw)
            )
        
        if not is_valid_password(password):
            return Response({
                "error": "Password must be at least 8 characters long, and include uppercase, lowercase, number, and special character."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({"message": "Password has been reset successfully."})
            else:
                return Response(
                    {"error": "This reset link is invalid or has expired."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid user."},
                status=status.HTTP_400_BAD_REQUEST
            )

# Update user's email and username
@api_view(['PATCH'])
def update_user_info(request):
    if not request.user.is_authenticated:
        return Response({'detail': 'Authentication required.'}, status=401)

    username = request.data.get('username')
    email = request.data.get('email')

    # Validation
    if not username or not email:
        return Response({'detail': 'Username and email are required.'}, status=400)

    # Validate username
    if not re.fullmatch(r'[a-zA-Z0-9 ]{1,50}', username) or username.strip() == '':
        return Response({
            'username': [
                'Username must be 1-50 characters, letters, numbers, and spaces only. Cannot be only spaces.'
            ]
        }, status=400)

    # Validate email
    try:
        validate_email(email)
    except ValidationError:
        return Response({'email': ['Enter a valid email address.']}, status=400)

    # Check if new username is taken by someone else
    if User.objects.filter(username=username).exclude(id=request.user.id).exists():
        return Response({'username': ['Username already exists.']}, status=400)

    # Check if new email is taken by someone else
    if User.objects.filter(email=email).exclude(id=request.user.id).exists():
        return Response({'email': ['This email is already in use.']}, status=400)

    # Update
    user = request.user
    user.username = username
    user.email = email
    user.save()

    return Response({
        'message': 'User info updated successfully.',
        'username': user.username,
        'email': user.email,
    })
    
# Change password for account
@csrf_exempt
@login_required
def change_password(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed.'}, status=405)

    try:
        data = json.loads(request.body)
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return JsonResponse({'error': 'Both current and new passwords are required.'}, status=400)

        user = request.user

        if not user.check_password(current_password):
            return JsonResponse({'error': 'Current password is incorrect.'}, status=400)

        # Custom password validation
        if len(new_password) < 8:
            return JsonResponse({'error': 'Password must be at least 8 characters long.'}, status=400)
        if not re.search(r'[A-Z]', new_password):
            return JsonResponse({'error': 'Password must contain at least one uppercase letter.'}, status=400)
        if not re.search(r'[a-z]', new_password):
            return JsonResponse({'error': 'Password must contain at least one lowercase letter.'}, status=400)
        if not re.search(r'[0-9]', new_password):
            return JsonResponse({'error': 'Password must contain at least one number.'}, status=400)
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            return JsonResponse({'error': 'Password must contain at least one special character.'}, status=400)

        # Save new password
        user.set_password(new_password)
        user.save()

        # Keep user logged in
        update_session_auth_hash(request, user)

        return JsonResponse({'message': 'Password updated successfully.'}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format.'}, status=400)

    except Exception as e:
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)
