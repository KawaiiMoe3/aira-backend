import os
import dj_database_url
from .settings import *
from .settings import BASE_DIR

ALLOWED_HOSTS = [os.environ.get('RENDER_EXTERNAL_HOSTNAME')]
CSRF_TRUSTED_ORIGINS = ['https://'+os.environ.get('RENDER_EXTERNAL_HOSTNAME')]

DEBUG = False
SECRET_KEY = os.environ.get('SECRET_KEY')

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CORS_ALLOWED_ORIGINS = [
    "https://aira-u106.onrender.com",  # React frontend URL
]
CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    "https://aira-u106.onrender.com", 
]
CSRF_COOKIE_NAME = "csrftoken"
# Allow React frontend to receive the CSRF token cookie
CSRF_COOKIE_SECURE = True    # Set to True in production (HTTPS)
CSRF_COOKIE_SAMESITE = 'None'  # or 'None' if cross-origin
CSRF_COOKIE_HTTPONLY = False  # Must be False so React can read it

# Ensure cookies work in cross-site (frontend-backend) communication
SESSION_COOKIE_SECURE = True          # Required if HTTPS
SESSION_COOKIE_SAMESITE = 'None'      # Required for cross-origin cookies
SESSION_COOKIE_HTTPONLY = True

CSRF_USE_SESSIONS = True

STORAGES = {
    "default" : {
        "BACKEND" : "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles" : {
        "BACKEND" : "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

DATABASES = {
    'default': dj_database_url.config(
        default = os.environ['DATABASE_URL'],
        conn_max_age = 600
    )
}

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kuala_Lumpur'

USE_I18N = True

USE_TZ = False
