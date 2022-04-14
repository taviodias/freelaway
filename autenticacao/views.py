from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib import auth
from django.contrib.messages import constants

def cadastro(request):
    if request.method == 'GET':
        if request.user.is_authenticated:
            return redirect('/home')
        return render(request, 'cadastro.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        r_password = request.POST.get('confirm-password')

        if not password == r_password:
            messages.add_message(request, constants.ERROR, 'As senhas estão diferentes')
            print('Senhas diferentes')
            return redirect('/auth/cadastro')

        if len(username.strip()) == 0 or len(password.strip()) == 0:
            messages.add_message(request, constants.ERROR, 'Algum campo ficou em branco')
            print('usuario ou senha em branco')
            return redirect('/auth/cadastro')

        user = User.objects.filter(username=username)
        if user.exists():
            messages.add_message(request, constants.ERROR, 'Já existe um usário com esse nome de usuário')
            print('usuario ja existe')
            return redirect('/auth/cadastro')

        try:
            user = User.objects.create_user(username = username, password = password)
            user.save()
            messages.add_message(request, constants.SUCCESS, 'Usuário criado com sucesso')
            return redirect('/auth/login')
        except:
            messages.add_message(request, constants.ERROR, 'Erro interno do sistema')
            print('erro criar usuario')
            return redirect('/auth/cadastro')

def login(request):
    if request.method == 'GET':
        if request.user.is_authenticated:
            return redirect('/home')
        return render(request, 'login.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = auth.authenticate(username=username, password=password)
        if not user:
            messages.add_message(request, constants.ERROR, 'Usuário ou senha inválido(s)')
            return redirect('/auth/login')
        else:
            auth.login(request, user)
            return redirect('/home')

def sair(request):
    auth.logout(request)
    return redirect('/auth/login')