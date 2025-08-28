from django.urls import path
from .views import RegisterAPIView, LoginAPIView, DepartmentPositionsAPIView

urlpatterns = [
	# app endpoints
	path('api/register/', RegisterAPIView.as_view(), name='api-register'),
	path('api/login/', LoginAPIView.as_view(), name='api-login'),
	path('api/departments/<str:department_key>/positions/', DepartmentPositionsAPIView.as_view(), name='api-department-positions'),
]
