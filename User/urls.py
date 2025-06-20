from django.urls import path,include
from . import views

urlpatterns = [
    path('', views.welcome, name = 'home'),
    path('signup/', views.signup, name = 'signup'),
    path('', include("django.contrib.auth.urls")),
    path('profile/', views.profile_view, name = 'profile'),
    path('profile/edit/', views.profile_edit, name = 'profile_edit'),
    path('user_list/', views.user_list, name = 'user_list'),
    path('profile/delete/', views.del_user, name = 'delete_acc'),
]
