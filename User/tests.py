from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from Post.models import Post
from Post.tests import VIEW_MIDDLEWARE


@override_settings(MIDDLEWARE=VIEW_MIDDLEWARE)
class AccountDeletionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("account", password="test-pass")
        self.post = Post.objects.create(author=self.user, title="Title", text="Text")
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.user)

    def test_get_is_confirmation_and_post_requires_csrf(self):
        response = self.client.get(reverse("delete_acc"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
        self.assertEqual(self.client.post(reverse("delete_acc")).status_code, 403)
        token = self.client.cookies["csrftoken"].value
        self.assertEqual(self.client.post(reverse("delete_acc"), {"csrfmiddlewaretoken": token}).status_code, 302)
        self.assertFalse(User.objects.filter(pk=self.user.pk).exists())
        self.assertFalse(Post.objects.filter(pk=self.post.pk).exists())
