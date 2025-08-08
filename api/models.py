from django.db import models
from django.contrib.auth.models import User

# Create your models here.

# Profile models
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    position = models.CharField(max_length=100, blank=True, null=True)
    summary = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    github = models.URLField(blank=True, null=True)
    portfolio = models.URLField(blank=True, null=True)
    other_link = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.user.username

class Education(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='educations')
    institution = models.CharField(max_length=255)
    degree = models.CharField(max_length=100, blank=True, null=True)
    field_of_study = models.CharField(max_length=100, blank=True, null=True)
    start_date = models.DateField()
    end_date = models.CharField(max_length=50, blank=True, null=True) # Store as "Present" if is_still_studying is true
    cgpa = models.CharField(max_length=10, blank=True, null=True)
    is_still_studying = models.BooleanField(default=False)

    def __str__(self):
        return self.institution

class Experience(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='experiences')
    company = models.CharField(max_length=255)
    role = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.CharField(max_length=50, blank=True, null=True) # Store as "Present" if is_still_working is true
    contributions = models.TextField(blank=True, null=True)
    skills = models.TextField(blank=True, null=True)
    is_still_working = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.role} at {self.company}"

class Certification(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='certifications')
    title = models.CharField(max_length=255)
    issuer = models.CharField(max_length=255, blank=True, null=True)
    date = models.DateField(blank=True, null=True)

    def __str__(self):
        return self.title

class Project(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='projects')
    title = models.CharField(max_length=255)
    description = models.TextField()
    technologies = models.CharField(max_length=255)
    live_link = models.URLField(blank=True, null=True)
    github_link = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.title

class Skill(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='skills')
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Language(models.Model):
    PROFICIENCY_CHOICES = [
        ('Fluent', 'Fluent'),
        ('Moderate', 'Moderate'),
        ('Basic', 'Basic'),
    ]
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, related_name='languages')
    name = models.CharField(max_length=50)
    proficiency = models.CharField(max_length=20, choices=PROFICIENCY_CHOICES)

    def __str__(self):
        return f"{self.name} ({self.proficiency})"
    
class ResumeAnalysis(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_resume = models.FileField(upload_to='resumes/', blank=True, null=True)
    ai_feedback = models.TextField(blank=True, null=True)
    enhanced_resume = models.TextField(blank=True, null=True)
    analysis_report = models.FileField(upload_to='analysis_reports/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    