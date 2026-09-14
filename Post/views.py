from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from .models import Post
from .forms import PostForm


@login_required(login_url="/login/")
def new_post(request):
    form = PostForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        post = form.save(commit=False)
        post.author = request.user
        post.save()
        return redirect("post_detail", pk=post.pk)
    return render(request, "main/new_post_form.html", {"form": form})


@login_required(login_url="/login/")
def post_detail(request, pk):
    return render(request, "main/post_detail.html", {"post": get_object_or_404(Post, pk=pk)})


@login_required(login_url="/login/")
def post_edit(request, pk):
    post = get_object_or_404(Post, pk=pk, author=request.user)
    form = PostForm(request.POST if request.method == "POST" else None, instance=post)
    if request.method == "POST" and form.is_valid():
        form.save()
        return redirect("post_detail", pk=post.pk)
    return render(request, "main/new_post_form.html", {"form": form})


@login_required(login_url="/login/")
def feed(request):
    return render(request, "main/feed.html", {"posts": Post.objects.all().order_by("-created_date")})


@login_required(login_url="/login/")
@require_POST
def post_deleted(request, pk):
    post = get_object_or_404(Post, pk=pk, author=request.user)
    post.delete()
    return render(request, "main/post_deleted.html", {"pk": pk})

