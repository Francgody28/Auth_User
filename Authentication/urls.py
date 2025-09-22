from django.urls import path
from .views import RegisterAPIView, LoginAPIView, DepartmentPositionsAPIView, ExternalAuthAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
	# app endpoints
	path('api/register/', RegisterAPIView.as_view(), name='api-register'),
	path('api/login/', LoginAPIView.as_view(), name='api-login'),
	path('api/departments/<str:department_key>/positions/', DepartmentPositionsAPIView.as_view(), name='api-department-positions'),
	path('api/external/auth/', ExternalAuthAPIView.as_view(), name='api-external-auth'),
	# JWT endpoints:
	path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
	path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
