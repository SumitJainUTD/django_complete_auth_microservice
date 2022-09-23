from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from config import settings


def create_link_for_email(user, host='localhost', scheme='http', reason='activate'):
    print(user)
    uid = urlsafe_base64_encode(force_bytes(user.id))
    token = PasswordResetTokenGenerator().make_token(user=user)
    link = scheme + '://' + host + '/api/users/' + reason + "/" + uid + "/" + token + "/"
    print(link)
    return link


def send_email(subject='', body='', sender=settings.DEFAULT_FROM_EMAIL, to=None, as_html=True):
    if as_html:
        message = EmailMultiAlternatives(
            subject=subject,
            body="mail testing",
            from_email=sender,
            to=[to]
        )
        message.attach_alternative(body, "text/html")
        message.send(fail_silently=False)
    else:
        send_mail(
            subject=subject,
            message=message,
            recipient_list=[to],
            from_email=sender,
            fail_silently=False,
        )
