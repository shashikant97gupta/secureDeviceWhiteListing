# backend/core/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('auth/init/', views.auth_init, name='auth-init'),          # returns encrypted HTML payload
    path('auth/verify-access/', views.verify_access, name='verify-access'),  # decrypt + check access
]
