from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('procesar/', views.procesar, name='procesar'),
    path('upload/', views.prueba01, name='upload_document'),
]