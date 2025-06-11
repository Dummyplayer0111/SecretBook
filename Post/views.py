from django.shortcuts import render, get_object_or_404, redirect
from .models import Post
from .forms import PostForm
from django.utils import timezone
from django.contrib.auth.decorators import login_required

@login_required(login_url = '/login/')
def new_post(request):
    if request.method == "POST":
        form = PostForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.published_date = timezone.now()
            post.save()
            return redirect('post_detail', uuid = post.uuid)
    else:
        form = PostForm()
        return render(request, 'main/new_post_form.html', {'form': form})
        
        
@login_required(login_url = '/login/')
def post_detail(request, pk):
    post = get_object_or_404(Post, pk = pk)
    return render(request, 'main/post_detail.html', {'post': post})
    
    
@login_required(login_url='/login/')
def post_edit(request, pk):
    post = get_object_or_404(Post, pk = pk)
    if request.method == 'POST' and request.user == post.author:
        form = PostForm(request.POST, instance = post)
        if form.is_valid():
            post = form.save(commit = False)
            post.author = request.user
            post.created_date = timezone.now()
            post.save()
            return redirect('post_detail', uuid = post.pk)
    elif request.user == post.author:
        form = PostForm(instance=post)
        return render(request, 'main/new_post_form.html', {'form': form})
        
@login_required(login_url = '/login/')
def feed(request):
    posts = Post.objects.all().order_by('created_date')
    return render(request, 'main/feed.html', {'posts':posts})
    
def post_deleted(request, pk):
    post = get_object_or_404(Post, pk = pk)
    if post.author == request.user:
        post.delete()
        return render(request, 'main/post_deleted.html', {'pn':pk})
    
