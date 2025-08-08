import re
import json
import os
import PyPDF2
import docx2txt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from django.contrib.auth.models import User
from .models import Profile, Language, Skill, Education, Experience, Project,  Certification, \
                    ResumeAnalysis
from .serializers import ProfileSerializer
from .utils import evaluate_profile_status

from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout as django_logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt, csrf_protect, ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.timezone import now
from django.conf import settings
from django.http import JsonResponse, FileResponse, Http404
from django.utils.dateformat import format

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
@ensure_csrf_cookie
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
            'last_login': request.user.last_login,
        })
    else:
        return Response({'isAuthenticated': False}, status=200)

# Get the token before making a post request
@api_view(['GET'])
@ensure_csrf_cookie
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
@csrf_protect
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

# Update profile info
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_info(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    # If the profile is exists, then display as the value of all input fields at the initial load
    if request.method == 'GET':
        serializer = ProfileSerializer(profile)
        return Response(serializer.data)

    # If the profile info is empty, save or if exists then update the values
    elif request.method == 'POST':
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile info updated.", "data": serializer.data})
        print(">>> Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=400)

# Update profile image
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_image(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        image_url = request.build_absolute_uri(profile.profile_image.url) if profile.profile_image else None
        return Response({'profile_image': image_url})

    elif request.method == 'POST':
        profile_image = request.FILES.get('profile_image')
        print("FILES:", request.FILES)

        if not profile_image:
            return Response({'error': 'No image uploaded'}, status=400)

        # === Validation ===
        # 1. Size check (1MB max)
        max_size = 1 * 1024 * 1024  # 1MB
        if profile_image.size > max_size:
            return Response({'error': 'Image file size must be less than 1MB'}, status=400)

        # 2. Format check
        valid_formats = ['image/png', 'image/jpeg', 'image/gif']
        print("Content type:", profile_image.content_type)
        if profile_image.content_type not in valid_formats:
            return Response({'error': 'Invalid image format. Only PNG, JPG, JPEG, and GIF are allowed.'}, status=400)
        
        # === Delete old image if exists ===
        if profile.profile_image and profile.profile_image.name:
            profile.profile_image.delete(save=False)

        # Save profile image
        profile.profile_image = profile_image
        profile.save()

        return Response({
            'message': 'Profile image saved successfully',
            'profile_image': request.build_absolute_uri(profile.profile_image.url)
        })

# Update profile summary
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_summary(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        return Response({'summary': profile.summary})

    elif request.method == 'POST':
        summary = request.data.get('summary', '').strip()
        
        # Validate summary length
        if len(summary) > 500:
            return Response({'summary': 'Summary cannot exceed 500 characters.'}, status=status.HTTP_400_BAD_REQUEST)
        
        profile.summary = summary
        profile.save()
        return Response({'message': 'Summary updated.', 'summary': profile.summary})

# Update profile's languages
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_languages(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        # Return existing languages
        data = [
            {"name": lang.name, "proficiency": lang.proficiency}
            for lang in profile.languages.all()
        ]
        return Response({"languages": data})

    elif request.method == 'POST':
        languages_data = request.data.get("languages", [])
        
        # Validation: If name is not empty, proficiency must also not be empty
        for lang in languages_data:
            name = lang.get("name", "").strip()
            proficiency = lang.get("proficiency", "").strip()

            if name and not proficiency:
                return Response(
                    {"error": f"Proficiency is required for language '{name}'."},
                    status=400
                )

        # Delete existing languages
        profile.languages.all().delete()

        # Create new languages
        for lang in languages_data:
            name = lang.get("name", "").strip()
            proficiency = lang.get("proficiency", "").strip()

            if name and proficiency:  # Only save if name and proficiency are filled
                Language.objects.create(
                    profile=profile,
                    name=name,
                    proficiency=proficiency
                )

        return Response({"message": "Languages saved successfully."})

# Update profile's skills
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_skills(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        data = [{"name": skill.name} for skill in profile.skills.all()]
        return Response({"skills": data})

    elif request.method == 'POST':
        skills_data = request.data.get("skills", [])
        
        # Validate all skills
        for skill in skills_data:
            name = skill.get("name", "").strip()
            if not name:
                return Response(
                    {"error": "Please fill in all skill names or remove empty ones."},
                    status=400
                )

        # Delete old skills
        profile.skills.all().delete()

        # Save new ones
        for skill in skills_data:
            name = skill.get("name", "").strip()
            if name:
                Skill.objects.create(profile=profile, name=name)

        return Response({"message": "Skills updated successfully."})

# Update profile's educations
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_educations(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        educations = profile.educations.all()
        data = [{
            "institution": edu.institution,
            "degree": edu.degree,
            "field_of_study": edu.field_of_study,
            "start_date": edu.start_date,
            "end_date": edu.end_date,
            "cgpa": edu.cgpa,
            "is_still_studying": edu.is_still_studying,
        } for edu in educations]
        return Response({"educations": data})

    elif request.method == 'POST':
        educations_data = request.data.get("educations", [])

        # Validate input
        for edu in educations_data:
            if not edu.get("institution") or not edu.get("start_date"):
                return Response(
                    {"error": "Please fill in all required fields or remove empty ones."},
                    status=400
                )

        # Delete old entries
        profile.educations.all().delete()

        # Save new entries
        for edu in educations_data:
            is_still_studying = edu.get("is_still_studying", False)
            end_date = "Present" if is_still_studying else edu.get("end_date") or None

            Education.objects.create(
                profile=profile,
                institution=edu.get("institution", "").strip(),
                degree=edu.get("degree", "").strip() or None,
                field_of_study=edu.get("field_of_study", "").strip() or None,
                start_date=edu.get("start_date"),
                end_date=end_date,
                cgpa=edu.get("cgpa", "").strip() or None,
                is_still_studying=is_still_studying
            )

        return Response({"message": "Educations updated successfully."})

# Update profile's professional experiences
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_experiences(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        data = [
            {
                "company": exp.company,
                "role": exp.role,
                "start_date": exp.start_date,
                "end_date": exp.end_date,
                "contributions": exp.contributions,
                "skills": exp.skills,
                "is_still_working": exp.is_still_working,
            }
            for exp in profile.experiences.all()
        ]
        return Response({"experiences": data})

    elif request.method == 'POST':
        experiences_data = request.data.get("experiences", [])

        # Validate required fields
        for exp in experiences_data:
            if not exp.get("company") or not exp.get("role") or not exp.get("start_date"):
                return Response(
                    {"error": "Please fill in all required fields or remove empty ones."},
                    status=400
                )

        # Delete existing experiences
        profile.experiences.all().delete()

        # Create new experiences
        for exp in experiences_data:
            is_still_working = exp.get("is_still_working", False)
            end_date = "Present" if is_still_working else exp.get("end_date", "")
            Experience.objects.create(
                profile=profile,
                company=exp.get("company", "").strip(),
                role=exp.get("role", "").strip(),
                start_date=exp.get("start_date"),
                end_date=end_date,
                contributions=exp.get("contributions", "").strip(),
                skills=exp.get("skills", "").strip(),
                is_still_working=is_still_working,
            )

        return Response({"message": "Experiences updated successfully."})

# Update profile's projects
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_projects(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        data = [{
            "title": project.title,
            "description": project.description,
            "technologies": project.technologies,
            "live_link": project.live_link,
            "github_link": project.github_link,
        } for project in profile.projects.all()]
        return Response({"projects": data})

    elif request.method == 'POST':
        projects_data = request.data.get("projects", [])

        # Validate input
        for proj in projects_data:
            if not proj.get("title") or not proj.get("description") or not proj.get("technologies"):
                return Response(
                    {"error": "Please fill in all required fields or remove empty ones."},
                    status=400
                )

        # Delete existing projects
        profile.projects.all().delete()

        # Create new projects
        for proj in projects_data:
            Project.objects.create(
                profile=profile,
                title=proj["title"],
                description=proj["description"],
                technologies=proj["technologies"],
                live_link=proj.get("live_link", ""),
                github_link=proj.get("github_link", "")
            )

        return Response({"message": "Projects updated successfully."})

# Update profile's certifications
@csrf_protect
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_certifications(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == 'GET':
        data = [{
            "title": cert.title,
            "issuer": cert.issuer,
            "date": cert.date,
        } for cert in profile.certifications.all()]
        return Response({"certifications": data})

    elif request.method == 'POST':
        certifications_data = request.data.get("certifications", [])

        for cert in certifications_data:
            if not cert.get("title"):
                return Response(
                    {"error": "Please fill in the 'Title' field for each certification or remove the empty one."},
                    status=400
                )

        profile.certifications.all().delete()

        for cert in certifications_data:
            Certification.objects.create(
                profile=profile,
                title=cert["title"],
                issuer=cert.get("issuer", ""),
                date=cert.get("date") or None
            )

        return Response({"message": "Certifications updated successfully."})

# Evaluation of profile status
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_status(request):
    try:
        profile = Profile.objects.get(user=request.user)
        status, message = evaluate_profile_status(profile)
        return Response({
            'status': status,
            'message': message,
        })
    except Profile.DoesNotExist:
        return Response({
            'status': 'Incomplete',
            'message': 'Profile not found. Please complete your profile.'
        }, status=404)

@api_view(['POST'])
@parser_classes([MultiPartParser])
@permission_classes([IsAuthenticated])
def resume_analyze(request):
    file = request.FILES.get('resume')
    ai_feedback = request.POST.get('ai_feedback')
    enhanced_resume = request.POST.get('enhanced_resume')

    if not file or not ai_feedback or not enhanced_resume:
        return Response({'error': 'Missing data'}, status=400)

    analysis = ResumeAnalysis.objects.create(
        user=request.user,
        uploaded_resume=file,
        ai_feedback=ai_feedback,
        enhanced_resume=enhanced_resume
    )

    return Response({'id': analysis.id})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def feedback_detail(request, pk):
    try:
        analysis = ResumeAnalysis.objects.get(pk=pk, user=request.user)
    except ResumeAnalysis.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    # Path for PDF
    date_str = analysis.created_at.strftime("%d%m%y")
    analysis_report_filename = f"{os.path.splitext(os.path.basename(analysis.uploaded_resume.name))[0]}{date_str}{analysis.id}_report.pdf"
    analysis_report_path = os.path.join(settings.MEDIA_ROOT, 'analysis_reports', analysis_report_filename)

    os.makedirs(os.path.dirname(analysis_report_path), exist_ok=True)

    # Generate PDF
    doc = SimpleDocTemplate(analysis_report_path)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>AI Feedback</b>", styles['Heading1']),
        Paragraph(analysis.ai_feedback or "No feedback provided", styles['Normal']),
        Spacer(1, 12),
        Paragraph("<b>Enhanced Resume</b>", styles['Heading1']),
        Paragraph(analysis.enhanced_resume or "No enhanced resume provided", styles['Normal']),
    ]
    doc.build(story)

    # Save file to model if not already saved
    if not analysis.analysis_report:
        analysis.analysis_report.name = f"analysis_reports/{analysis_report_filename}"
        analysis.save()

    return Response({
        'ai_feedback': analysis.ai_feedback,
        'enhanced_resume': analysis.enhanced_resume
    })
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def resume_analysis_history(request):
    user = request.user
    analyses = ResumeAnalysis.objects.filter(user=user).order_by('-created_at')

    data = []
    for analysis in analyses:
        resume_name = analysis.uploaded_resume.name.split('/')[-1] if analysis.uploaded_resume else ''
        title = os.path.splitext(resume_name)[0]  # Remove extension for title
        
        date_str = analysis.created_at.strftime("%d%m%y") # DDMMYY
        analysis_report_filename = f"{title}{date_str}{analysis.id}_report.pdf"
        
        data.append({
            'id': analysis.id,
            'title': title,
            'date': format(analysis.created_at, 'd M Y, H:i'),  # e.g., DD Month YYYY, H:M
            'uploadedResume': resume_name,
            'analysisReport': analysis_report_filename
        })

    return Response(data)

def download_uploaded_resume(request, filename):
    file_path = os.path.join(settings.MEDIA_ROOT, 'resumes', filename)
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        raise Http404("File does not exist")
    
def download_analysis_report(request, filename):
    file_path = os.path.join(settings.MEDIA_ROOT, 'analysis_reports', filename)
    if os.path.exists(file_path):
        response = FileResponse(open(file_path, 'rb'), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        raise Http404("File does not exist")
    
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_selected_analyzed_history(request):
    ids = request.data.get('ids', [])

    if not ids:
        return Response({"error": "No IDs provided"}, status=status.HTTP_400_BAD_REQUEST)

    records = ResumeAnalysis.objects.filter(id__in=ids, user=request.user)
    deleted_count = 0

    for record in records:
        # 1. Delete the uploaded resume if it exists
        if record.uploaded_resume and record.uploaded_resume.path and os.path.isfile(record.uploaded_resume.path):
            try:
                os.remove(record.uploaded_resume.path)
            except Exception as e:
                print(f"Error deleting file {record.uploaded_resume.path}: {e}")
                
        # 2. Delete generated analysis report if exists
        if record.analysis_report:
            resume_title = os.path.splitext(os.path.basename(record.uploaded_resume.name))[0]
            date_str = record.created_at.strftime("%d%m%y")
            analysis_report_filename = f"{resume_title}{date_str}{record.id}_report.pdf"
            analysis_report_path = os.path.join(settings.MEDIA_ROOT, "analysis_reports", analysis_report_filename)

            if os.path.isfile(analysis_report_path):
                try:
                    os.remove(analysis_report_path)
                except Exception as e:
                    print(f"Error deleting analysis report {analysis_report_path}: {e}")

        # Then delete the database record
        record.delete()
        deleted_count += 1

    return Response({"message": f"{deleted_count} item(s) deleted"}, status=status.HTTP_200_OK)
