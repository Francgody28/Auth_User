from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from .serializers import RegisterSerializer, LoginSerializer, DEPT_POSITION_MAP
from .models import AuthenticatedUser, DEPARTMENT_CHOICES, POSITION_CHOICES
from rest_framework_simplejwt.tokens import RefreshToken
import os

signer = TimestampSigner()

# Dashboard mappings pointing to System A (localhost:5173) - for non-PSMS users
POSITION_TO_DASHBOARD = {
    # Laboratory
    'register': 'http://localhost:5173/laboratory/registry-dashboard',
    'laboratory_technician': 'http://localhost:5173/laboratory/technician-dashboard',
    'head_division_laboratory': 'http://localhost:5173/laboratory/division-dashboard',
    'head_department_laboratory': 'http://localhost:5173/laboratory/department-dashboard',
    # Research
    'researcher': 'http://localhost:5173/research/researcher-dashboard',
    'assistant_researcher': 'http://localhost:5173/research/assistant-dashboard',
    'head_division_research': 'http://localhost:5173/research/division-dashboard',
    'head_department_research': 'http://localhost:5173/research/department-dashboard',
    # Administration (non-planning)
    'head_division_administration': 'http://localhost:5173/administration/division-dashboard',
}

ROLE_TO_DASHBOARD = {
    'admin': 'http://localhost:2809/admin-dashboard',
    'manager': 'http://localhost:2809manager-dashboard',
    'staff': 'http://localhost:2809/staff-dashboard',
    'guest': 'http://localhost:2809/guest-dashboard',
}

class RegisterAPIView(APIView):
    """
    POST /api/register/
    GET /api/register/  -> returns available departments and positions
    """
    def get(self, request):
        # build readable mapping for frontend
        pos_labels = dict(POSITION_CHOICES)
        dept_labels = dict(DEPARTMENT_CHOICES)
        data = []
        for dept_key, dept_label in DEPARTMENT_CHOICES:
            allowed_positions = DEPT_POSITION_MAP.get(dept_key, set())
            positions = [{"key": pos_key, "label": pos_labels[pos_key]} for pos_key in allowed_positions if pos_key in pos_labels]
            data.append({"key": dept_key, "label": dept_label, "positions": positions})
        return Response({"departments": data})

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "User created"}, status=status.HTTP_201_CREATED)

class DepartmentPositionsAPIView(APIView):
    """
    GET /api/departments/<department_key>/positions/
    """
    def get(self, request, department_key):
        dept_keys = {k for k, _ in DEPARTMENT_CHOICES}
        if department_key not in dept_keys:
            return Response({"detail": "Invalid department"}, status=status.HTTP_400_BAD_REQUEST)

        pos_labels = dict(POSITION_CHOICES)
        allowed_positions = DEPT_POSITION_MAP.get(department_key, set())
        positions = [{"key": pos_key, "label": pos_labels[pos_key]} for pos_key in allowed_positions if pos_key in pos_labels]
        return Response({"positions": positions})

class LoginAPIView(APIView):
    """
    POST /api/login/
    Body: { "username": "...", "password": "..." }
    Returns: Direct redirect URL with SSO token
    """
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            user = AuthenticatedUser.objects.get(username__iexact=username)
        except AuthenticatedUser.DoesNotExist:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT tokens for System A
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # Generate SSO token for PSMS (expires in 5 minutes)
        sso_payload = f"{user.id}:{user.username}:{user.email}:{user.role}:{user.department}:{user.position}"
        sso_token = signer.sign(sso_payload)

        # PSMS dashboard mappings with SSO token - PORT 3000
        PSMS_DASHBOARDS = {
    'planning_officer': f'http://localhost:2809/planning-dashboard?sso_token={sso_token}',
    'statistic_officer': f'http://localhost:2809/statistics-dashboard?sso_token={sso_token}',
    'head_division_planning': f'http://localhost:2809/head-of-division-dashboard?sso_token={sso_token}',
    'head_department_planning': f'http://localhost:2809/head-of-department-dashboard?sso_token={sso_token}',
    'director_general': f'http://localhost:2809/director-general-dashboard?sso_token={sso_token}',
        }

        # Check if user should go to PSMS with SSO
        if user.position in PSMS_DASHBOARDS:
            redirect_url = PSMS_DASHBOARDS[user.position]
            redirect_to_psms = True
        else:
            # Other positions go to their respective dashboards in System A
            redirect_url = POSITION_TO_DASHBOARD.get(user.position) or ROLE_TO_DASHBOARD.get(user.role, 'http://localhost:5173/guest-dashboard')
            redirect_to_psms = False

        return Response({
            "username": user.username,
            "token": access_token,
            "refresh": refresh_token,
            "sso_token": sso_token,
            "redirect": redirect_url,
            "role": user.role,
            "department": user.department,
            "position": user.position,
            "redirect_to_psms": redirect_to_psms
        })

class ExternalAuthAPIView(APIView):
    """
    POST /api/external/auth/
    Headers: X-API-KEY: <shared-key>
    Body: { "sso_token": "<signed-token>" }
    For PSMS to validate SSO tokens
    """
    def post(self, request):
        # Validate API key
        provided_key = request.headers.get('X-API-KEY') or request.META.get('HTTP_X_API_KEY')
        expected_key = os.environ.get('EXTERNAL_API_KEY', 'system-ab-shared-key-2024')
        if not provided_key or provided_key != expected_key:
            return Response({"detail": "Forbidden - Invalid API Key"}, status=status.HTTP_403_FORBIDDEN)

        data = request.data or {}
        sso_token = data.get('sso_token')
        
        if not sso_token:
            return Response({"detail": "sso_token required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode SSO token with 5-minute expiry
            raw = signer.unsign(sso_token, max_age=300)  # 5 minutes
            parts = raw.split(':', 5)
            if len(parts) != 6:
                return Response({"detail": "Invalid token format"}, status=status.HTTP_401_UNAUTHORIZED)
            
            user_id, username, email, role, department, position = parts
            user = AuthenticatedUser.objects.filter(id=user_id).first()
            if not user:
                return Response({"detail": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
                
        except SignatureExpired:
            return Response({"detail": "SSO token expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except BadSignature:
            return Response({"detail": "Invalid SSO token signature"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"detail": "Invalid SSO token"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "employee_number": user.employee_number,
            "role": user.role,
            "department": user.department,
            "position": user.position,
            "authenticated": True
        })
