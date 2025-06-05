from django.urls import path, include
from . import views

urlpatterns = [
    path('profile/post_new', views.new_post, name = 'post_new'),
    path('post/<int:pn>/', views.post_detail, name ='post_detail'),
    path('post_edit/<int:pn>/', views.post_edit, name ='post_edit'),
    path('feed/', views.feed, name ='feed'),
    path('post_deleted/<int:pn>/', views.post_deleted , name ='delete')
]
