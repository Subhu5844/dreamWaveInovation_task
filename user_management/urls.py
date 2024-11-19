"""
URL configuration for user_management project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from accounts import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('create_user/', views.create_user, name='create_user'),
    path('users/', views.list_users, name='list_users'),
    path('login/', views.user_login, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.user_logout, name='logout'),
    path('user/update/<int:user_id>/', views.update_user, name='update_user'),
    path('user/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    path('create_reset_token/<int:user_id>/', views.create_password_reset_token, name='create_reset_token'),
    path('reset_tokens/', views.list_password_reset_tokens, name='list_reset_tokens'),
    path('assign_role_permission/<int:user_id>/', views.assign_role_permission, name='assign_role_permission'),
    path('role_permissions/', views.list_role_permissions, name='list_role_permissions'),
]
