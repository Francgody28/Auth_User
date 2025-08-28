from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from .serializers import RegisterSerializer, LoginSerializer, DEPT_POSITION_MAP
from .models import AuthenticatedUser, DEPARTMENT_CHOICES, POSITION_CHOICES
import os

signer = TimestampSigner()

# central mappings (reuse in LoginAPIView and external API)
POSITION_TO_DASHBOARD = {
	# Planning & Administration
	'planning_officer': '/planning/planning-officer-dashboard',
	'statistic_officer': '/planning/statistics-dashboard',
	'head_division_planning': '/planning/division-dashboard',
	'head_division_administration': '/administration/division-dashboard',
	'head_department_planning': '/planning/department-dashboard',
	# Laboratory
	'register': '/laboratory/registry-dashboard',
	'laboratory_technician': '/laboratory/technician-dashboard',
	'head_division_laboratory': '/laboratory/division-dashboard',
	'head_department_laboratory': '/laboratory/department-dashboard',
	# Research
	'researcher': '/research/researcher-dashboard',
	'assistant_researcher': '/research/assistant-researcher',
	'head_division_research': '/research/division-dashboard',
	'head_department_research': '/research/department-dashboard',
	# Directorate
	'director_general': '/directorate/general-dashboard',
}

ROLE_TO_DASHBOARD = {
	'admin': '/admin-dashboard',
	'manager': '/manager-dashboard',
	'staff': '/staff-dashboard',
	'guest': '/guest-dashboard',
}

class RegisterAPIView(APIView):
	"""
	POST /api/register/
	GET /api/register/  -> returns available departments and positions
	Required for POST: username, email (must end with @Zafiri.go.tz), employee_number, full_name, role, department, position, password, confirm_password
	"""
	def get(self, request):
		# build readable mapping for frontend
		pos_labels = dict(POSITION_CHOICES)
		dept_labels = dict(DEPARTMENT_CHOICES)
		data = []
		for dept_key, dept_label in DEPARTMENT_CHOICES:
			allowed_positions = DEPT_POSITION_MAP.get(dept_key, set())
			positions = [{"key": p, "label": pos_labels.get(p, p)} for p in allowed_positions]
			data.append({
				"key": dept_key,
				"label": dept_label,
				"positions": positions
			})
		return Response({"departments": data})

	def post(self, request):
		serializer = RegisterSerializer(data=request.data)
		# raise_exception=True will return proper 400 with serializer errors
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response({"detail": "User created"}, status=status.HTTP_201_CREATED)

# New view: return positions for a given department key
class DepartmentPositionsAPIView(APIView):
	"""
	GET /api/departments/<department_key>/positions/
	Returns positions allowed for the specified department.
	"""
	def get(self, request, department_key):
		dept_keys = {k for k, _ in DEPARTMENT_CHOICES}
		if department_key not in dept_keys:
			return Response({"detail": "Unknown department."}, status=status.HTTP_400_BAD_REQUEST)

		pos_labels = dict(POSITION_CHOICES)
		allowed_positions = DEPT_POSITION_MAP.get(department_key, set())
		positions = [{"key": p, "label": pos_labels.get(p, p)} for p in allowed_positions]
		return Response({"department": department_key, "positions": positions})

class LoginAPIView(APIView):
	"""
	POST /api/login/
	Body: { "username": "...", "password": "..." }
	Returns: { "username": "...", "redirect": "/some-dashboard", "token": "<signed token>", "position": "..." }
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

		# generate a simple signed token with timestamp (validity can be checked later)
		raw = f"{user.id}:{user.email}"
		token = signer.sign(raw)

		# determine redirect: prefer position mapping, then role, then guest
		redirect = POSITION_TO_DASHBOARD.get(user.position) or ROLE_TO_DASHBOARD.get(user.role, '/guest-dashboard')

		# include department and position in response so frontend can use role selection
		return Response({
			"username": user.username,
			"token": token,
			"redirect": redirect,
			"role": user.role,
			"department": user.department,
			"position": user.position
		})

# New endpoint for external systems to resolve user dashboard / profile
class ExternalAuthAPIView(APIView):
	"""
	POST /api/external/auth/
	Headers: X-API-KEY: <shared-key>
	Body options:
	  - { "username": "...", "password": "..." }
	  - { "token": "<signed-token>" }   (token produced by LoginAPIView signer.sign)
	Response:
	  200 { username, role, department, position, dashboard }
	  401/403/400 on failure
	"""
	def post(self, request):
		# validate API key
		provided_key = request.headers.get('X-API-KEY') or request.META.get('HTTP_X_API_KEY')
		expected_key = os.environ.get('EXTERNAL_API_KEY')
		if not expected_key:
			return Response({"detail": "External API key not configured on server."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		if not provided_key or provided_key != expected_key:
			return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

		data = request.data or {}
		user = None

		# Option A: token authentication (signed by signer)
		token = data.get('token')
		if token:
			try:
				raw = signer.unsign(token)  # format: "<id>:<email>"
				user_id = raw.split(':', 1)[0]
				user = AuthenticatedUser.objects.filter(id=user_id).first()
				if not user:
					return Response({"detail": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
			except SignatureExpired:
				return Response({"detail": "Token expired"}, status=status.HTTP_401_UNAUTHORIZED)
			except BadSignature:
				return Response({"detail": "Invalid token signature"}, status=status.HTTP_401_UNAUTHORIZED)

		# Option B: username + password
		else:
			username = (data.get('username') or "").strip()
			password = data.get('password')
			if not username or not password:
				return Response({"detail": "Provide token or username and password."}, status=status.HTTP_400_BAD_REQUEST)
			user = AuthenticatedUser.objects.filter(username__iexact=username).first()
			if not user or not user.check_password(password):
				return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

		# determine dashboard url (position preferred)
		dashboard = POSITION_TO_DASHBOARD.get(user.position) or ROLE_TO_DASHBOARD.get(user.role, '/guest-dashboard')

		return Response({
			"username": user.username,
			"role": user.role,
			"department": user.department,
			"position": user.position,
			"dashboard": dashboard,
		})
