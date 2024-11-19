from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser, PasswordResetToken, RolePermission
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import Group, Permission


User = get_user_model()

# Create User View
@csrf_exempt
def create_user(request):
    """Handles the creation of a new user."""
    if request.method == 'POST':
        # Fetch form data
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        mobile_number = request.POST['mobile_number']
        whatsapp_number = request.POST.get('whatsapp_number')  # Optional
        company_name = request.POST['company_name']
        registration_no = request.POST['registration_no']
        vat_no = request.POST['vat_no']
        address = request.POST['address']
        role = request.POST['role']
        designation = request.POST.get('designation')  # Optional
        password = request.POST['password']

        # Save user data
        try:
            user = CustomUser.objects.create_user(
                email=email,
                mobile_number=mobile_number,
                password=password,
                first_name=first_name,
                last_name=last_name,
                whatsapp_number=whatsapp_number,
                company_name=company_name,
                registration_no=registration_no,
                vat_no=vat_no,
                address=address,
                role=role,
                designation=designation,
            )
            return HttpResponse("User created successfully.")
        except Exception as e:
            return HttpResponse(f"Error: {e}", status=400)

    # Render the form
    return render(request, 'create_user.html')




def user_login(request):
    """Handles user login."""
    if request.method == 'POST':
        email_or_mobile = request.POST.get('email_or_mobile')
        password = request.POST.get('password')

        # Check if input is email or mobile and authenticate
        try:
            user = CustomUser.objects.get(
                email=email_or_mobile
            ) if '@' in email_or_mobile else CustomUser.objects.get(
                mobile_number=email_or_mobile
            )
        except CustomUser.DoesNotExist:
            user = None

        if user:
            user = authenticate(request, username=user.email, password=password)
            if user:
                login(request, user)
                return redirect('dashboard')  # Redirect to dashboard
            else:
                messages.error(request, 'Invalid password.')
        else:
            messages.error(request, 'Invalid email or mobile number.')

    return render(request, 'login.html')


@login_required
def dashboard(request):
    """Dashboard view accessible only to authenticated users."""
    if not request.user.is_authenticated:
        return redirect('login')

    # Retrieve data for the dashboard
    total_users = CustomUser.objects.count()
    active_users = CustomUser.objects.filter(is_active=True).count()
    total_reset_tokens = PasswordResetToken.objects.count()
    total_roles = RolePermission.objects.count()
    
    context = {
        'user': request.user,
        'total_users': total_users,
        'active_users': active_users,
        'total_reset_tokens': total_reset_tokens,
        'total_roles': total_roles,
    }
    return render(request, 'dashboard.html', context)


def user_logout(request):
    """Logs out the user."""
    logout(request)
    return redirect('login')


# List Users View
def list_users(request):
    users = CustomUser.objects.all()
    return render(request, 'list_users.html', {'users': users})


# Update User View
@csrf_exempt
def update_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    roles = Group.objects.all()  # Fetch all roles
    print('this is roles in update_user',roles)
    permissions = Permission.objects.all()  # Fetch all permissions

    if request.method == 'POST':
        data = request.POST
        
        # Update user details
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.mobile_number = data.get('mobile_number', user.mobile_number)
        user.company_name = data.get('company_name', user.company_name)
        user.save()

        # Assign Role
        group = None
        role_id = data.get('role')
        if role_id:
            group = Group.objects.filter(id=role_id).first()
            if group:
                user.groups.clear()  # Clear existing roles
                user.groups.add(group)  # Assign the new role

        # Assign Permissions
        selected_permissions = data.getlist('permissions')  # Get selected permission IDs
        permission_list = []
        if selected_permissions:
            permission_list = Permission.objects.filter(id__in=selected_permissions).values_list('codename', flat=True)
            user.user_permissions.clear()  # Clear existing permissions
            permissions_to_add = Permission.objects.filter(id__in=selected_permissions)
            user.user_permissions.add(*permissions_to_add)  # Add new permissions

        # Update RolePermission model
        RolePermission.objects.update_or_create(
            user=user,
            role=group.name if group else "Unassigned",  # Assign the group name or "Unassigned"
            defaults={
                "permissions": list(permission_list),  # Save permissions as a list of codenames
            },
        )

        return JsonResponse({'message': 'User updated successfully'})

    return render(request, 'update_user.html', {
        'user': user,
        'roles': roles,
        'permissions': permissions
    })


# Delete User View
@csrf_exempt
def delete_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    
    if request.method == 'POST':
        user.delete()
        return JsonResponse({'message': 'User deleted successfully'})

    return render(request, 'delete_user.html', {'user': user})


# Create Password Reset Token View
@csrf_exempt
def create_password_reset_token(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    
    if request.method == 'POST':
        token = PasswordResetToken.objects.create(user=user, token='your-generated-token')
        return JsonResponse({'message': 'Password reset token created successfully', 'token': token.token})

    return render(request, 'create_reset_token.html', {'user': user})


# List Password Reset Tokens View
def list_password_reset_tokens(request):
    tokens = PasswordResetToken.objects.all()
    return render(request, 'list_reset_tokens.html', {'tokens': tokens})


# Role Permission View (Assign/Manage Permissions)
@csrf_exempt
def assign_role_permission(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == 'POST':
        data = request.POST
        role = data.get('role')
        permissions = data.get('permissions')  # Expecting JSON or comma-separated list
        
        if role:
            role_permission = RolePermission.objects.create(
                user=user,
                role=role,
                permissions=permissions  # Store as a dictionary or JSON format
            )
            return JsonResponse({'message': 'Role permissions assigned successfully'})
    
    return render(request, 'assign_role_permissions.html', {'user': user})


# List Role Permissions View
def list_role_permissions(request):
    role_permissions = RolePermission.objects.all()
    print('this is list_role api ', role_permissions)
    return render(request, 'list_role_permissions.html', {'role_permissions': role_permissions})
