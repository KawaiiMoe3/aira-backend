"""
WSGI config for resume_analyzer project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

# Development run 'settings.py' or Deployment run 'deployment_settings.py'
settings_module = 'resume_analyzer.deployment_settings' if 'RENDER_EXTERNAL_HOSTNAME' in os.environ else 'resume_analyzer.settings'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'resume_analyzer.settings')

application = get_wsgi_application()
