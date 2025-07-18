from django.urls import path
from . import views

urlpatterns = [
    # Test connection between Django and React
    path('test/', views.test_connection),
    
    # API Endpoints for main features
    path('signup/', views.sign_up),
    path('signin/', views.sign_in),
    path('logout/', views.sign_out),
    
    # API for checking user's logged in status
    path('user/', views.get_logged_in_user),
    # API for update user's info
    path('user/update/', views.UpdateUserInfoView.as_view()),
    path('user/change-password/', views.change_password),
    
    # API for generate csrf token
    path('csrf/', views.get_csrf_token),
    
    # API forgot password and reset password
    path('password-reset/', views.ForgotPasswordView.as_view()),
    path('password-reset-confirm/', views.ResetPasswordConfirmView.as_view()),
]
