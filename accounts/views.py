from django.http import HttpResponseRedirect
from django.contrib.auth import login as direct_login
from django.contrib.auth import authenticate
from django.contrib.auth.views import login, logout
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render
from django.contrib.auth import update_session_auth_hash
from online_financial_management_system.utils import get_alerts, render_alert_page_with_data, redirect_with_data
from accounts.forms import SignUpForm
from online_financial_management_system.decorators import custom_login_required
from receipts.models import Receipt
from salary.models import Salary
from tables.models import Table

from companies.models import Company
import re
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from .models import Staff
#from werkzeug.security import check_password_hash, generate_password_hash
from django.shortcuts import render, HttpResponse, redirect
from django.core.mail import send_mail
#from verify_email.email_handler import send_verification_email
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes,force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .token import account_activation_token   
from django.template.loader import render_to_string 
from receipts.models import Receipt,Item
import yfinance as yf
from investment.models import Invest
def custom_login(request):
    data = {}

    # Collect alerts.
    alerts = get_alerts(request)
    data['alerts'] = alerts

    # Test whether the user has logged in.
    #print("user: ",request.user.email )
    print("data: ",data)

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        #form = SignUpForm(request, request.POST)
        print("enter")
        #username = form.cleaned_data.get('username')
        #password = form.cleaned_data['password1']
        print(username, password)
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            current_site = get_current_site(request)
            subject = 'Welcome to TMS System'
            message = render_to_string('accounts/golin.html', {  
                    'user': user,  
                    'domain': current_site.domain,
                }) 
            email_from = 'fadishah784@gmail.com'
            #recipient_list = ["zaheerfarman50@gmail.com",]
            print(user.email)
            recipient_list = [user.email,]
            send_mail( subject, message, email_from, recipient_list )

            return login(request, template_name='accounts/login.html', extra_context=data)

    if request.user.is_authenticated():
        return redirect_with_data(request, data, '/info/')
    else:
        print("heloo1")
        return login(request, template_name='accounts/login.html', extra_context=data)


@custom_login_required
def custom_logout(request, data):
    data['alert'] = ('success', 'Logout successfully!', 'You have successfully logged out!')
    data['redirect_link'] = '/index/'
    return logout(request, template_name='alert_and_redirect.html', extra_context=data)


@custom_login_required
def change_password(request, data):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)

            # Success
            data['alerts'].append(('success', 'Password changed!', 'Your password was successfully updated.'))
            return render(request, 'info/index.html', data)
    else:
        form = PasswordChangeForm(request.user)

    return render(request, 'accounts/change_password.html', {'form': form}, data)

def dashboard(request):
    data = Receipt.objects.all()
    #print(data)
    amount=0
    total=0
    loan=0
    for obj in data:
        # Perform operations with the retrieved objects
        #print(obj.total_amount)
        amount=amount+obj.total_amount
    context = [{'amount': amount}]
    data = Salary.objects.all()
    for obj in data:
        # Perform operations with the retrieved objects
        #print(obj.total)
        total=total+obj.total
    context = [{'amount': amount,'total': total}]
    data = Invest.objects.all()
    for obj in data:
        # Perform operations with the retrieved objects
        #print(obj.total_amount)
        loan=loan+obj.total_amount
    
    
    context = [{'amount': amount,'total': total,'loan':loan}]
    #print(user)
    data=work(request)
    print(data)
    #print(data['6'])
    context = {'amount': amount,'total': total,'loan':loan,'receipt_records':data}
    salary=salary1(request)
    print(salary)
    table=table1(request)
    print(table)
    context = {'amount': amount,'total': total,'loan':loan,'receipt_records':data,'salary_records':salary,'table_records':table}
    return render(request,'accounts/dashboard.html',context)

def signup(request):
    # Collect alerts.
    alerts = get_alerts(request)

    # Test whether the user has logged in.
    if request.user.is_authenticated():
        alerts.append(('info', 'You have logged in!', 'If you want to sign up a new account, please log out first.'))
        request.session['alerts'] = alerts
        return HttpResponseRedirect('/info/')

    data = {'alerts': alerts}

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()  # load the staff instance created by the signal
            user.staff.full_name = form.cleaned_data.get('full_name')
            user.staff.age = form.cleaned_data.get('age')
            user.is_active=False
            current_site = get_current_site(request)
            subject = 'Welcome to TMS System'
            message = render_to_string('accounts/token1.html', {  
                    'user': user,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                    'token':account_activation_token.make_token(user),  
                }) 
            email_from = 'fadishah784@gmail.com'
            recipient_list = [user.email,]
            send_mail( subject, message, email_from, recipient_list )
            user.save()
            #raw_password = form.cleaned_data.get('password1')
            #user = authenticate(username=user.username, password=raw_password)
            #direct_login(request, user)
            #return redirect_with_data(request, data, '/info/')
            return HttpResponse("Verification link sent to your mail. Kindly activate your account...")
    else:
        form = SignUpForm()

    data['form'] = form
    return render(request, 'accounts/signup.html', data)

def reset(request):
    if request.method == 'POST':
        email = request.POST.get('email', None) 
        print(email)
        User = get_user_model()
        if User.objects.filter(email=email).exists():
            print("enters")
            username = User.objects.get(email=email.lower()).username
            print(username)
            new_user = User.objects.get(username=username)
            current_site = get_current_site(request)
            subject = 'Password Reset'
            message = render_to_string('accounts/token.html', {  
                    'user': new_user,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(new_user.pk)),  
                    'token':account_activation_token.make_token(new_user),  
                }) 
            print(new_user.pk)
            print("Message is ok....")
            email_from =  'fadishah784@gmail.com'
            recipient_list = [email,]
            send_mail( subject, message, email_from, recipient_list )
            return redirect('/accounts/login')
        else:
            return HttpResponse("Email doesn't Exist...")
    return render(request,'accounts/reset.html')

def activate(request, uidb64, token):  
    User=None
    print("handshake")
    try:  
        uid = force_str(urlsafe_base64_decode(uidb64))  
        print(uid)
        User = get_user_model()
        user = User.objects.get(pk=uid)  
        print("hello2")
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        if request.method=='POST':
            pass1=request.POST.get('password1', None)
            pass2=request.POST.get('password2', None) 
            if not pass1==pass2:
                pass
            elif (len(pass1)<8):
                pass
            elif not re.search("[a-z]", pass1):
                pass
            elif not re.search("[A-Z]", pass1):
                pass
            elif not re.search("[0-9]", pass1):
                pass
            else:
                user.password = make_password(pass1)
                user.save()
                return redirect('/accounts/login')

        return render(request,'accounts/reset_password.html')  
    else:  
        return HttpResponse('Activation link is invalid!')
    
def activate1(request, uidb64, token):  
    User 
    try:  
        uid = force_str(urlsafe_base64_decode(uidb64))  
        user = User.objects.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        user.is_active = True  
        user.save()  
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')  
    else:  
        return HttpResponse('Activation link is invalid!')
    
def work(request):
    #print(request.id)
    data={}
    data2=[]
    data1 = Receipt.objects.all()
    for obj in data1:
        str2=str(obj.creator)
        str1=str(request.user)
        if str1==str2:
            data2.append(obj)
    return data2

def salary1(request):
    data={}
    data2=[]
    data1 = Salary.objects.all()
    for obj in data1:
        str2=str(obj.payer)
        str1=str(request.user)
        if str1==str2:
            data2.append(obj)
    return data2

def table1(request):
    data={}
    data2=[]
    data1 = Table.objects.all()
    for obj in data1:
        str2=str(obj.creator)
        str1=str(request.user)
        if str1==str2:
            data2.append(obj)
    return data2
