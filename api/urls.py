from django.urls import path
from . import views

urlpatterns = [
    path('test/', views.test_connection),
    path('signup/', views.sign_up),
    path('signin/', views.sign_in),
]
