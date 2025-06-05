from django.conf import settings 
from django.contrib import admin
from django.urls import path,include
from django.conf.urls.static import static
from User import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", include("User.urls")),
    path("", include("Post.urls"))
]
