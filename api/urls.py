from django.urls import path
from . import views

urlpatterns = [
    path('test/', views.test_connection),
    path('signup/', views.sign_up),
    path('signin/', views.sign_in),
    path('user/', views.get_logged_in_user),
    path('csrf/', views.get_csrf_token),
    path('logout/', views.sign_out),
]
