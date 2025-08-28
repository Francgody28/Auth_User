from django.contrib import admin
from .models import AuthenticatedUser

@admin.register(AuthenticatedUser)
class AuthenticatedUserAdmin(admin.ModelAdmin):
	list_display = ('username','full_name', 'employee_number', 'email', 'phone_number', 'role', 'department', 'position', 'created_at')
	search_fields = ('username','email', 'employee_number', 'full_name', 'phone_number')
	list_filter = ('role','department','position')
