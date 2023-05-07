"""zhixue_mark_v2 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from mark import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('student_info/',views.student_info),
    path('login/',views.login_page),
    path('cmark/',views.temp_c),
    path('index/',views.index),
    path('logout/',views.logout),
    path('get_exam_data/',views.get_exam_data),
    path('manage/',views.adminboard),
    path('list_exam/',views.list_exam),
]
