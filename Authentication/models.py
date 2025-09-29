from django.db import models
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password, check_password, identify_hasher
from django.utils import timezone

ROLE_CHOICES = (
	('admin', 'Admin'),
	('manager', 'Manager'),
	('staff', 'Staff'),
	('guest', 'Guest'),
)

DEPARTMENT_CHOICES = (
	('planning', 'Planning and Administration'),
	('laboratory', 'Laboratory'),
	('research', 'Department of Research'),
	('directorate', 'Directorate General'),
)

POSITION_CHOICES = (
	# Planning & Administration
	('planning_officer', 'Planning Officer'),
	('statistic_officer', 'Statistic Officer'),
	('head_division_planning', 'Head of Division (Planning)'),
	('head_division_administration', 'Head of Division (Administration)'),
	('head_department_planning', 'Head of Department (Planning & Admin)'),
	# Laboratory
	('register', 'Register'),
	('laboratory_technician', 'Laboratory Technician'),
	('head_division_laboratory', 'Head of Division (Laboratory)'),
	('head_department_laboratory', 'Head of Department (Laboratory)'),
	# Research
	('researcher', 'Researcher'),
	('assistant_researcher', 'Assistant Researcher'),
	('head_division_research', 'Head of Division (Research)'),
	('head_department_research', 'Head of Department (Research)'),
	# Directorate
	('director_general', 'Director General'),
)

def validate_zafiri_email(value):
	# domain check (case-insensitive)
	if not isinstance(value, str) or not value.lower().endswith('@zafiri.go.tz'):
		raise ValidationError('Email must be a @Zafiri.go.tz address.')

class AuthenticatedUser(models.Model):
	username = models.CharField(max_length=150, unique=True)
	email = models.EmailField(unique=True, validators=[validate_zafiri_email])
	employee_number = models.CharField(max_length=50, unique=True)
	full_name = models.CharField(max_length=200)
	role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='guest')
	department = models.CharField(max_length=30, choices=DEPARTMENT_CHOICES, default='planning')
	position = models.CharField(max_length=50, choices=POSITION_CHOICES, default='planning_officer')
	phone_number = models.CharField(max_length=20, unique=True)
	password = models.CharField(max_length=128)  # hashed password
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	date_joined = models.DateTimeField(default=timezone.now)
	last_login = models.DateTimeField(blank=True, null=True)
	is_active = models.BooleanField(default=True)

	def set_password(self, raw_password):
		self.password = make_password(raw_password)

	def check_password(self, raw_password):
		return check_password(raw_password, self.password)

	def clean(self):
		# reuse email validator (will raise ValidationError if not valid)
		validate_zafiri_email(self.email)

	def save(self, *args, **kwargs):
		# If password is not already a recognized hashed format, hash it.
		already_hashed = False
		if self.password:
			try:
				identify_hasher(self.password)
				already_hashed = True
			except Exception:
				already_hashed = False

		if not already_hashed and self.password:
			# hash only when raw password present
			self.set_password(self.password)
		super().save(*args, **kwargs)

	def __str__(self):
		return f"{self.username} - {self.full_name} ({self.employee_number})"
