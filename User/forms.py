from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError

class CustomUserCreationForm(UserCreationForm): 

    username = forms.CharField(label = 'Username', min_length = 5 , max_length = 40)  
    email = forms.EmailField(label = 'E-mail')  
    password1 = forms.CharField(label = 'Password', widget = forms.PasswordInput)  
    password2 = forms.CharField(label = 'Confirm Password', widget = forms.PasswordInput)   
    def clean_email(self):  
        email = (self.cleaned_data.get('email', '')).lower()
        new = User.objects.filter(email = email)  
        if new.count():  
            raise ValidationError(" Email Already Exists")  
        return email
  
    def clean_password2(self):  
        password1 = self.cleaned_data['password1']  
        password2 = self.cleaned_data['password2']  
  
        if password1 and password2 and password1 != password2:  
            raise ValidationError("Passwords don't match")  
        return password2  
  
    def save(self, commit = True):  
        user = User.objects.create_user(  
            self.cleaned_data['username'],  
            self.cleaned_data['email'],  
            self.cleaned_data['password1']  
        )  
        return user
        
class User_edit(forms.ModelForm):
    username = forms.CharField(label = 'Username', min_length = 5 , max_length = 40)  
    email = forms.EmailField(label = 'E-mail') 
    class Meta:
        model = User
        fields = ['username', 'email']
        
    def clean_email(self):  
        email= (self.cleaned_data.get('email', '')).lower()
        new = User.objects.filter(email = email)  
        if email != self.instance.email:
            if new.count():  
                raise ValidationError("User with Email Already Exists")  
        return email
        
