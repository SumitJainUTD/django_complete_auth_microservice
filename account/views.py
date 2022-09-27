# Create your views here.
from django.core.mail import EmailMultiAlternatives
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password, make_password
from .serializers import UserCreateSerializer, UserProfileSerializer, UserRegistrationSerializer, \
    SendPasswordResetEmailSerializer, PasswordResetSerializer, UserChangePasswordSerializer, SendVerifyEmailSerializer, \
    VerifyEmailSerializer
from .utils import create_link_for_email, send_email
from .models import OldPasswords
User = get_user_model()
# Generate Token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegisterView(APIView):
    def post(self, request):
        data = request.data

        serializer = UserCreateSerializer(data=data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.create(serializer.validated_data)
        token = get_tokens_for_user(user=user)
        # SendVerifyEmailView().send_verification_email(request=request, user=user)
        user = UserRegistrationSerializer(user)

        response = {'token': token, 'user': user.data, 'message': "Registration Successful"}
        return Response(response, status=status.HTTP_201_CREATED)


class UserProfileView(APIView):
    print("zzzz")
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        user = UserProfileSerializer(user)

        return Response(user.data, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': user})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        response = {'message': "Password has been changed"}
        return Response(response, status=status.HTTP_200_OK)
    #TODO: log user out on change password


class SendPasswordResetEmailView(APIView):
    def post(self, request):
        host = request.META['HTTP_HOST']
        scheme = request.META['wsgi.url_scheme']
        print(host)
        serializer = SendPasswordResetEmailSerializer(data=request.data, context={'host': host, 'scheme': scheme})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        response = {'message': "Mail has been sent to the registered email address"}
        return Response(response, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    def post(self, request, uid, token):
        serializer = PasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        response = {'message': "Password has been reset"}
        return Response(response, status=status.HTTP_200_OK)


class SendVerifyEmailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def send_verification_email(self, request, user):
        try:
            # user = request.user
            host = request.META['HTTP_HOST']
            scheme = request.META['wsgi.url_scheme']
            link = create_link_for_email(user=user, host=host, scheme=scheme, reason="verify-email")

            # context = {
            #     'user_name': user.data['first_name'],
            #     'protocol': 'https' if request.is_secure() else "http",
            #     'domain': request.get_host(),
            # }
            mail_context = {
                'user_name': user.first_name,
                'verify_link': link,
            }
            html_message = render_to_string('account/verify_email.html', mail_context)
            subject = "Verify Email Address for Your Company"
            send_email(to=user.email, body=html_message, subject=subject)
            return True
        except:
            raise ValueError("Unable to send email for verification")

    def post(self, request):
        if self.send_verification_email(request=request, user=request.user):
            response = {'message': "Email for verification has been sent"}
            return Response(response, status=status.HTTP_200_OK)


class VerifyEmailView(APIView):
    def get(self, request, uid, token):
        serializer = VerifyEmailSerializer(data=request.data, context={'uid': uid, 'token': token})
        if not serializer.is_valid():
            return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        response = {'message': "Email and Account has been verified"}
        return JsonResponse(response, status=status.HTTP_200_OK)

class LogoutView(APIView):
    print("logout")
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class LogoutAllView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        print(request.user.id)
        print(tokens)
        for token in tokens:
            t, _ = BlacklistedToken.objects.get_or_create(token=token)

        return Response(status=status.HTTP_205_RESET_CONTENT)
