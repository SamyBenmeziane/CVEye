from django.urls import path
from .views import install_view

urlpatterns = [
    path("install/", install_view, name="install"),
]