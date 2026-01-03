from django.urls import path
from .views import (
    RegisterView, VerifyAccountView,
    PasswordResetRequestView, PasswordResetConfirmView,
    LogoutView, api_root
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('', api_root, name='api-root'),
    path('register/', RegisterView.as_view(), name='register'),
    path('verify/<uidb64>/<token>/', VerifyAccountView.as_view(), name='verify'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
