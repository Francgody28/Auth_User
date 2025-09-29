from django.contrib import admin
from django import forms
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
import re
from .models import AuthenticatedUser, DEPARTMENT_CHOICES, POSITION_CHOICES
from .serializers import DEPT_POSITION_MAP

def password_policy_validator(password):
    """Validate password policy for admin forms"""
    if not password:
        return
    
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r'[^\w\s]', password):
        errors.append("Password must contain at least one special character.")
    if errors:
        raise ValidationError(errors)

class PasswordInputWithToggle(forms.PasswordInput):
    """Custom password input widget with clean black/white eye toggle"""
    
    def __init__(self, attrs=None):
        if attrs is None:
            attrs = {}
        attrs.update({
            'style': 'width: calc(100% - 40px); display: inline-block;',
            'autocomplete': 'new-password'
        })
        super().__init__(attrs)
    
    def render(self, name, value, attrs=None, renderer=None):
        # Get the base password input
        password_input = super().render(name, value, attrs, renderer)
        
        # Create unique IDs for this field
        field_id = attrs.get('id', name) if attrs else name
        
        # Add the toggle button with clean black/white SVG eye icon
        toggle_html = f'''
        <div style="position: relative; display: inline-block; width: 100%;">
            {password_input}
            <button type="button" 
                    id="toggle_{field_id}" 
                    onclick="togglePassword('{field_id}')"
                    style="
                        position: absolute;
                        right: 8px;
                        top: 50%;
                        transform: translateY(-50%);
                        background: none;
                        border: none;
                        cursor: pointer;
                        color: #333;
                        padding: 0;
                        height: 20px;
                        width: 20px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    "
                    title="Show Password">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                </svg>
            </button>
        </div>
        
        <script>
        function togglePassword(fieldId) {{
            const passwordField = document.getElementById(fieldId);
            const toggleButton = document.getElementById('toggle_' + fieldId);
            
            if (passwordField.type === 'password') {{
                // Show password - change to "eye with slash" icon
                passwordField.type = 'text';
                toggleButton.innerHTML = `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                        <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                `;
                toggleButton.title = 'Hide Password';
            }} else {{
                // Hide password - change to normal "eye" icon
                passwordField.type = 'password';
                toggleButton.innerHTML = `
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                `;
                toggleButton.title = 'Show Password';
            }}
        }}
        </script>
        '''
        
        return mark_safe(toggle_html)

class AuthenticatedUserCreationForm(forms.ModelForm):
    """Form for creating new users - matches your serializer fields exactly"""
    
    password = forms.CharField(
        label="Password",
        widget=PasswordInputWithToggle(attrs={'placeholder': 'Enter password'}),
        help_text="Password must be 8+ chars with uppercase, lowercase, digit, and special character.",
    )
    confirm_password = forms.CharField(
        label="Confirm Password",
        widget=PasswordInputWithToggle(attrs={'placeholder': 'Confirm password'}),
        help_text="Re-enter the password",
    )
    
    class Meta:
        model = AuthenticatedUser
        # Exact same fields as your serializer
        fields = (
            'username', 'email', 'employee_number', 'full_name',
            'role', 'department', 'position', 'phone_number'
        )
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Username'}),
            'email': forms.EmailInput(attrs={'placeholder': 'user@zafiri.go.tz'}),
            'employee_number': forms.TextInput(attrs={'placeholder': 'Employee Number'}),
            'full_name': forms.TextInput(attrs={'placeholder': 'Full Name'}),
            'phone_number': forms.TextInput(attrs={'placeholder': '0712345678'}),
        }
        help_texts = {
            'email': 'Must be a valid @zafiri.go.tz email address',
            'phone_number': 'Must be exactly 10 digits',
            'employee_number': 'Unique employee number',
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set role choices to match your serializer
        self.fields['role'].choices = [
            ('admin', 'Admin'),
            ('manager', 'Manager'),
            ('staff', 'Staff'),
            ('guest', 'Guest')
        ]
        self.fields['role'].initial = 'staff'
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and not email.lower().endswith('@zafiri.go.tz'):
            raise ValidationError("Email must be a valid @zafiri.go.tz address")
        return email
    
    def clean_phone_number(self):
        phone = self.cleaned_data.get('phone_number', '').strip()
        if not re.fullmatch(r'^\d{10}$', phone):
            raise ValidationError("Phone number must be exactly 10 digits.")
        return phone
    
    def clean_employee_number(self):
        emp_num = self.cleaned_data.get('employee_number', '').strip()
        if not emp_num:
            raise ValidationError("Employee number cannot be empty.")
        
        # Check for uniqueness
        if AuthenticatedUser.objects.filter(employee_number=emp_num).exists():
            raise ValidationError("Employee number must be unique.")
        
        return emp_num
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        password_policy_validator(password)
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Password confirmation validation (same as your serializer)
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password:
            if password != confirm_password:
                raise ValidationError({
                    "confirm_password": "Passwords do not match."
                })
        
        # Department/position validation (same as your serializer)
        dept = cleaned_data.get('department')
        pos = cleaned_data.get('position')
        if dept and pos:
            allowed = DEPT_POSITION_MAP.get(dept, set())
            if pos not in allowed:
                raise ValidationError({
                    "position": "Position is not valid for the selected department."
                })
        
        return cleaned_data
    
    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get('password')
        user.set_password(password)  # Hash the password
        
        if commit:
            user.save()
        return user

class AuthenticatedUserChangeForm(forms.ModelForm):
    """Form for editing existing users"""
    
    new_password = forms.CharField(
        label="New Password",
        widget=PasswordInputWithToggle(attrs={'placeholder': 'Enter new password (optional)'}),
        help_text="Leave empty to keep current password. Must be 8+ chars with uppercase, lowercase, digit, and special character.",
        required=False
    )
    confirm_password = forms.CharField(
        label="Confirm New Password",
        widget=PasswordInputWithToggle(attrs={'placeholder': 'Confirm new password'}),
        help_text="Re-enter the new password",
        required=False
    )
    
    class Meta:
        model = AuthenticatedUser
        fields = (
            'username', 'email', 'employee_number', 'full_name',
            'role', 'department', 'position', 'phone_number', 'is_active'
        )
        help_texts = {
            'email': 'Must be a valid @zafiri.go.tz email address',
            'phone_number': 'Must be exactly 10 digits',
            'employee_number': 'Unique employee number',
        }
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and not email.lower().endswith('@zafiri.go.tz'):
            raise ValidationError("Email must be a valid @zafiri.go.tz address")
        return email
    
    def clean_phone_number(self):
        phone = self.cleaned_data.get('phone_number', '').strip()
        if not re.fullmatch(r'^\d{10}$', phone):
            raise ValidationError("Phone number must be exactly 10 digits.")
        return phone
    
    def clean_employee_number(self):
        emp_num = self.cleaned_data.get('employee_number', '').strip()
        if not emp_num:
            raise ValidationError("Employee number cannot be empty.")
        
        # Check for uniqueness (excluding current instance)
        existing = AuthenticatedUser.objects.filter(employee_number=emp_num)
        if self.instance.pk:
            existing = existing.exclude(pk=self.instance.pk)
        if existing.exists():
            raise ValidationError("Employee number must be unique.")
        
        return emp_num
    
    def clean_new_password(self):
        password = self.cleaned_data.get('new_password')
        if password:  # Only validate if password is provided
            password_policy_validator(password)
        return password
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Password confirmation validation
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        
        # If either password field has a value, both must match
        if new_password or confirm_password:
            if new_password != confirm_password:
                raise ValidationError({
                    "confirm_password": "Passwords do not match."
                })
        
        # Department/position validation
        dept = cleaned_data.get('department')
        pos = cleaned_data.get('position')
        if dept and pos:
            allowed = DEPT_POSITION_MAP.get(dept, set())
            if pos not in allowed:
                raise ValidationError({
                    "position": "Position is not valid for the selected department."
                })
        
        return cleaned_data
    
    def save(self, commit=True):
        user = super().save(commit=False)
        
        # Handle password setting
        new_password = self.cleaned_data.get('new_password')
        if new_password:
            user.set_password(new_password)
        
        if commit:
            user.save()
        return user

@admin.register(AuthenticatedUser)
class AuthenticatedUserAdmin(admin.ModelAdmin):
    """Admin interface matching your serializer fields exactly"""
    
    # Use different forms for add/change
    add_form = AuthenticatedUserCreationForm
    form = AuthenticatedUserChangeForm
    
    # List display
    list_display = ('username', 'full_name', 'employee_number', 'email', 
                   'phone_number', 'department', 'position', 'role', 'is_active', 'created_at')
    
    # Filters
    list_filter = ('department', 'position', 'role', 'is_active', 'created_at')
    
    # Search
    search_fields = ('username', 'email', 'employee_number', 'full_name', 'phone_number')
    
    # Ordering
    ordering = ('username',)
    
    # Read-only fields
    readonly_fields = ('created_at', 'updated_at')
    
    # Fieldsets for editing existing users
    fieldsets = (
        ('Authentication', {
            'fields': ('username', 'new_password', 'confirm_password')
        }),
        ('Personal Information', {
            'fields': ('full_name', 'email', 'employee_number', 'phone_number')
        }),
        ('Organizational Information', {
            'fields': ('department', 'position', 'role')
        }),
        ('Account Status', {
            'fields': ('is_active',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )
    
    # Fieldsets for creating NEW users - matches your serializer exactly
    add_fieldsets = (
        ('Authentication', {
            'classes': ('wide',),
            'fields': ('username', 'password', 'confirm_password'),
        }),
        ('Personal Information', {
            'classes': ('wide',),
            'fields': ('full_name', 'email', 'employee_number', 'phone_number'),
        }),
        ('Organizational Information', {
            'classes': ('wide',),
            'fields': ('department', 'position', 'role'),
        }),
    )
    
    def get_form(self, request, obj=None, **kwargs):
        """Use different forms for add vs change"""
        if obj is None:  # Adding new user
            return self.add_form
        else:  # Editing existing user
            return self.form
    
    def get_fieldsets(self, request, obj=None):
        """Use add_fieldsets for new users, regular fieldsets for editing"""
        if not obj:  # Creating new user
            return self.add_fieldsets
        return super().get_fieldsets(request, obj)
    
    # Custom actions
    actions = ['activate_users', 'deactivate_users']
    
    def activate_users(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} users were successfully activated.')
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} users were successfully deactivated.')
    deactivate_users.short_description = "Deactivate selected users"
