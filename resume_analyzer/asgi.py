"""
ASGI config for resume_analyzer project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

# Development run 'settings.py' or Deployment run 'deployment_settings.py'
settings_module = 'resume_analyzer.deployment_settings' if 'RENDER_EXTERNAL_HOSTNAME' in os.environ else 'resume_analyzer.settings'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'resume_analyzer.settings')

application = get_asgi_application()
