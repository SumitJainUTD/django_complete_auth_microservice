from django.contrib.auth.hashers import check_password, make_password
from django.http import HttpResponse
from django.template.loader import render_to_string
from rest_framework import serializers, status
from django.contrib.auth import get_user_model, password_validation
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from django.core import exceptions
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from .models import OldPasswords
from .utils import create_link_for_email, send_email
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

User = get_user_model()


class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'middle_name', 'last_name', 'email', 'password')

    def validate(self, data):
        user = User(**data)
        password = data.get('password')
        try:
            password_validation.validate_password(password=password, user=user)
        except exceptions.ValidationError as e:
            serializers_error = serializers.as_serializer_error(e)
            raise exceptions.ValidationError(
                {'password': serializers_error['non_field_errors']}
            )
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        if 'middle_name' in validated_data:
            user.middle_name = validated_data['middle_name']
        return user


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'middle_name', 'last_name',
                  'email')


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'middle_name', 'last_name',
                  'email', 'last_login', 'is_email_verified')


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context.get('user')
        try:
            if password != password2:
                raise ValidationError("password and confirm password does not match")
            password_validation.validate_password(password=password)

            if not self.check_old_passwords(user=user, new_password=password):
                raise ValidationError("Cannot set to previous 8 passwords")

            user.set_password(password)
            user.save()
        except exceptions.ValidationError as e:
            serializers_error = serializers.as_serializer_error(e)
            raise exceptions.ValidationError(
                {'password': serializers_error['non_field_errors']}
            )
        return data

    def check_old_passwords(self, user, new_password):
        prev_passwords = OldPasswords.objects.filter(user=user)
        for pwd in prev_passwords:
            if check_password(new_password, pwd.password):
                return False
        if len(prev_passwords) == 8:
            record = OldPasswords.objects.order_by('created_at')[0]
            record.delete()

        instance = OldPasswords(
            user=user,
            password=make_password(new_password)
        )
        instance.save()
        return True


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        host = self.context.get('host')
        scheme = self.context.get('scheme')
        print(email)
        try:
            user = User.objects.get(email=email.lower())
            if user is not None:
                link = create_link_for_email(user=user, host=host, scheme=scheme, reason="reset-password")
                mail_context = {
                    'user_name': user.first_name,
                    'user_email': user.email,
                    'link': link
                }

                html_message = render_to_string('account/password_reset_email.html', mail_context)
                subject = "Reset Your Recogno Password"
                send_email(to=user.email, body=html_message, subject=subject)
                return True
            else:
                raise ValidationError("Not registered user")
        except:
            raise ValidationError("Not registered user")

        return attrs


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password')
        uid = self.context.get('uid')
        token = self.context.get('token')
        try:
            if password != password2:
                raise ValidationError("password and confirm password does not match")
            password_validation.validate_password(password=password)
            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                raise ValidationError("Token is not Valid or Expired")

            if not UserChangePasswordSerializer.check_old_passwords(user=user, new_password=password):
                raise ValidationError("Cannot set to previous 8 passwords")

            user.set_password(password)
            user.save()
        except exceptions.ValidationError as e:
            serializers_error = serializers.as_serializer_error(e)
            raise exceptions.ValidationError(
                {'password': serializers_error['non_field_errors']}
            )
        return data


class SendVerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        user = self.context.get('user')
        host = self.context.get('host')
        scheme = self.context.get('scheme')
        link = create_link_for_email(user=user, host=host, scheme=scheme, reason="verify-email")
        print(link)
        return attrs


class VerifyEmailSerializer(serializers.Serializer):

    def validate(self, data):
        uid = self.context.get('uid')
        token = self.context.get('token')
        try:
            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                raise ValidationError("Token is not Valid or Expired")
            user.is_email_verified = True
            user.save()
        except exceptions.ValidationError as e:
            serializers_error = serializers.as_serializer_error(e)
            raise exceptions.ValidationError(
                {'password': serializers_error['non_field_errors']}
            )
        return data


# override the token refresh since after refresh the new  refresh token was not
# getting added to the obtain token which was further used for logout all devices

class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)
    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs["refresh"])

        data = {"access": str(refresh.access_token)}

        if api_settings.ROTATE_REFRESH_TOKENS:
            auth = JWTAuthentication()
            user = auth.get_user(validated_token=refresh)
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    # Attempt to blacklist the given refresh token
                    refresh.blacklist()
                except AttributeError:
                    # If blacklist app not installed, `blacklist` method will
                    # not be present
                    pass

            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()

            OutstandingToken.objects.create(
                user=user,
                jti=refresh[api_settings.JTI_CLAIM],
                token=str(refresh),
                created_at=refresh.current_time,
                expires_at=datetime_from_epoch(refresh['exp'])
            )

            data["refresh"] = str(refresh)

        return data
