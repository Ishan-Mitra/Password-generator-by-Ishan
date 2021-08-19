from django.conf import settings
from django.http.response import HttpResponse, HttpResponseBadRequest
from django.core.mail import send_mail
from random import randint
from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def send_message(request):
    if request.method == 'POST':
        to_email = request.POST['email']
        otp_var = randint(100001, 999999)
        send_mail("Password Manager by Ishan otp",
        f"<h1>Your otp is : {otp_var}</h1>",
        settings.EMAIL_HOST_USER,
        [to_email],
        fail_silently=False)
        return HttpResponse("Email Sent")
    else:
        return HttpResponseBadRequest("404")