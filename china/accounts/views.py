from rest_framework.views import APIView
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse
from .serializers import RegisterSerializer, PasswordResetSerializer, SetNewPasswordSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse

@api_view(['GET'])
def api_root(request):
    return Response({
        "register": reverse('register', request=request),
        "verify": "verify/<uidb64>/<token>/",
        "login": reverse('login', request=request),
        "token_refresh": reverse('token_refresh', request=request),
        "password_reset": reverse('password_reset', request=request),
        "password_reset_confirm": "password-reset-confirm/<uidb64>/<token>/",
        "logout": reverse('logout', request=request),
    })

# -----------------------------
# Root API - shows all endpoints
# -----------------------------
from rest_framework.decorators import api_view

@api_view(['GET'])
def api_root(request):
    """
    API root endpoint that lists all available authentication endpoints.
    """
    return Response({
        "register": reverse('register', request=request),
        "verify": "verify/<uidb64>/<token>/",
        "login": reverse('login', request=request),
        "token_refresh": reverse('token_refresh', request=request),
        "password_reset": reverse('password_reset', request=request),
        "password_reset_confirm": "password-reset-confirm/<uidb64>/<token>/",
        "logout": reverse('logout', request=request),
    })


# -----------------------------
# Register API
# -----------------------------
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        user.is_active = False  # Inactive until verification
        user.save()
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_link = f"http://localhost:8000/api/auth/verify/{uid}/{token}/"
        print("Verification link:", verification_link)


# -----------------------------
# Account Verification API
# -----------------------------
class VerifyAccountView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Account verified successfully"})
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)


# -----------------------------
# Password Reset Request
# -----------------------------
class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"http://localhost:8000/api/auth/password-reset-confirm/{uid}/{token}/"
            print("Password reset link:", reset_link)
        except User.DoesNotExist:
            pass
        return Response({"message": "Password reset link sent if email exists"})


# -----------------------------
# Password Reset Confirm
# -----------------------------
class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token):
            user.set_password(serializer.validated_data['password'])
            user.save()
            return Response({"message": "Password has been reset successfully"})
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)


# -----------------------------
# Logout API (JWT)
# -----------------------------

class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=400)
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully"})
        except Exception:
            return Response({"error": "Invalid token"}, status=400)