# from django.shortcuts import render, redirect
# from django.contrib import messages 
# from django.http import HttpResponseRedirect
# from django.contrib.auth.models import User 
from django.contrib.auth import authenticate, login

# # Create your views here.


# def signup(request):
#     if request.method=='POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         password2 = request.POST.get('confirm-password')

#         if password != password2: 
#             messages.error(request, 'Invalid password')
#             return HttpResponseRedirect (request.path_info)

    
#         else: 
#             User.objects.create_user(username=username, password=password2)
#             return redirect('login')

#     return render(request, 'signup/signup.html')


# def login_user(request):
#     if request.method=='POST':
#         username = request.POST.get('username')
#         password = request.POST.get('password')

#         userobj = authenticate(username=username, password=password)
#         login(request,userobj)
#         return redirect('home')
#     return render(request, 'login/login.html')

import random
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings

# Function to generate a random 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Function to send OTP to the user's email
def send_otp_email(user_email, otp):
    subject = "Your OTP Code"
    message = f"Your OTP code is {otp}. It is valid for 5 minutes."
    from_email = settings.EMAIL_HOST_USER  # Ensure this is set in your settings.py
    send_mail(subject, message, from_email, [user_email])

# Signup view where the OTP is generated and sent
def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('confirm-password')
        email = request.POST.get('email')

        # Check if passwords match
        if password != password2:
            messages.error(request, 'Passwords do not match!')
            return HttpResponseRedirect(request.path_info)

        # Check if the email is already used
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email is already registered.')
            return HttpResponseRedirect(request.path_info)

        # Generate OTP
        otp = generate_otp()

        # Save OTP and other user details in session for later verification
        request.session['otp'] = otp
        request.session['email'] = email
        request.session['username'] = username
        request.session['password'] = password2

        # Send OTP email
        send_otp_email(email, otp)

        # Redirect to OTP verification page
        return redirect('verify_otp')

    return render(request, 'signup/signup.html')

# OTP Verification view to verify the OTP entered by the user
def verify_otp(request):
    if request.method == 'POST':
        otp_entered = request.POST.get('otp')

        # Compare entered OTP with the one stored in session
        if otp_entered == request.session.get('otp'):
            # Create the user once OTP is verified
            username = request.session.get('username')
            password = request.session.get('password')
            email = request.session.get('email')

            user = User.objects.create_user(username=username, password=password, email=email)
            user.save()

            # Clear session data
            del request.session['otp']
            del request.session['email']
            del request.session['username']
            del request.session['password']

            # Log the user in
            user = authenticate(username=username, password=password)
            login(request, user)

            return redirect('home')  # Redirect to home after successful signup

        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    return render(request, 'signup/verify_otp.html')
