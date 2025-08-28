from rest_framework import serializers
import re
from .models import AuthenticatedUser, validate_zafiri_email, DEPARTMENT_CHOICES, POSITION_CHOICES

# helper mapping for validation
DEPT_POSITION_MAP = {
    'planning': {
        'planning_officer','statistic_officer','head_division_planning','head_division_administration','head_department_planning'
    },
    'laboratory': {
        'register','laboratory_technician','head_division_laboratory','head_department_laboratory'
    },
    'research': {
        'researcher','assistant_researcher','head_division_research','head_department_research'
    },
    'directorate': {
        'director_general'
    },
}

def password_policy(value):
    """Raise serializers.ValidationError if password does not meet policy."""
    errs = []
    if not value or len(value) < 8:
        errs.append("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', value):
        errs.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', value):
        errs.append("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', value):
        errs.append("Password must contain at least one digit.")
    if not re.search(r'[^\w\s]', value):
        errs.append("Password must contain at least one special character.")
    if errs:
        raise serializers.ValidationError(errs)


class RegisterSerializer(serializers.ModelSerializer):
    # attach validator to guarantee field-level validation always runs
    password = serializers.CharField(write_only=True, required=True, validators=[password_policy], min_length=8)
    confirm_password = serializers.CharField(write_only=True, required=True)
    department = serializers.ChoiceField(choices=DEPARTMENT_CHOICES, required=True)
    position = serializers.ChoiceField(choices=POSITION_CHOICES, required=True)
    phone_number = serializers.CharField(required=True)

    class Meta:
        model = AuthenticatedUser
        fields = (
            'username', 'email', 'employee_number', 'full_name',
            'role', 'department', 'position', 'phone_number',
            'password', 'confirm_password'
        )

    def validate_email(self, value):
        validate_zafiri_email(value)
        return value

    def validate_employee_number(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Employee number cannot be empty.")
        return value

    def validate_phone_number(self, value):
        if not re.fullmatch(r'^\+?\d{7,15}$', value):
            raise serializers.ValidationError("Enter a valid phone number (7-15 digits, optional leading +).")
        return value

    def validate(self, attrs):
        # confirm_password check
        pw = attrs.get('password')
        confirm = attrs.pop('confirm_password', None)
        if pw != confirm:
            raise serializers.ValidationError({"password": ["Passwords do not match."]})

        # defensive: re-apply policy so even if field-level was bypassed it's enforced
        if pw:
            password_policy(pw)

        # department/position relationship validation
        dept = attrs.get('department')
        pos = attrs.get('position')
        if dept and pos:
            allowed = DEPT_POSITION_MAP.get(dept, set())
            if pos not in allowed:
                raise serializers.ValidationError({"position": ["Position is not valid for the selected department."]})
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = AuthenticatedUser(**validated_data)
        # ensure password is hashed explicitly
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
	username = serializers.CharField()
	password = serializers.CharField(write_only=True)

	def validate_username(self, value):
		if not value or not value.strip():
			raise serializers.ValidationError("Username is required.")
		return value.strip()