from django.urls import path, include
from . import views

urlpatterns = [
    path('profile/post_new', views.new_post, name = 'post_new'),
    path('post/<uuid:uid>/', views.post_detail, name ='post_detail'),
    path('post_edit/<uuid:uid>/', views.post_edit, name ='post_edit'),
    path('feed/', views.feed, name ='feed'),
    path('post_deleted/<uuid:uid>/', views.post_deleted , name ='delete')
]
