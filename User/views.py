from django.shortcuts import render,redirect
from .forms import CustomUserCreationForm,User_edit
from Post.models import Post
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import logout


def welcome(request):
    if request.user.is_authenticated:
        return redirect('profile')
    else:
        return render(request , 'main/home.html', {})
    
def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'main/signup.html',{'form': form})
        
@login_required(login_url = '/login/')
def profile_view(request):
    posts = Post.objects.filter(author = request.user).order_by('created_date')
    return render(request, 'main/profile.html', {'posts': posts})
 
 
@login_required(login_url = '/login/')
def profile_edit(request):
    if request.method == 'POST':
        form = User_edit(request.POST, instance = request.user)
        if form.is_valid():
            form.save()
            return redirect('profile')
    else:
        form = User_edit(instance = request.user)
    return render(request, 'main/sign_down.html', {'form': form})

@login_required(login_url = '/login/')
def user_list(request):
    all = User.objects.all()
    return render(request, 'main/list_users.html', {'users':all})
    

@login_required(login_url = '/login/')
def del_user(request):
    user = request.user 
    posts = Post.objects.filter(author = request.user)
    for post in posts:
        post.delete()
    user.delete()
    return redirect('signup')
    


        



