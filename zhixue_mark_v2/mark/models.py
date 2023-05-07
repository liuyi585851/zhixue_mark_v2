from django.db import models

# Create your models here.
class ApiLogs(models.Model):
    trace_id = models.CharField(max_length=256)
    request_time = models.CharField(max_length=128)
    request_url = models.CharField(max_length=2048)
    request_ip = models.CharField(max_length=128)
    request_method = models.CharField(max_length=128)
    log_type = models.CharField(max_length=128)
    action = models.CharField(max_length=128)
    status = models.CharField(max_length=128)
    message = models.CharField(max_length=256)

class LoginLogs(models.Model):
    log_id = models.CharField(max_length=256)
    login_time = models.CharField(max_length=128)
    login_from = models.CharField(max_length=128)
    username = models.CharField(max_length=128)
    password = models.CharField(max_length=128)
    status = models.CharField(max_length=128)
    message = models.CharField(max_length=256)

class Users(models.Model):
    user_name = models.CharField(max_length=128)
    user_code = models.CharField(max_length=128)
    user_id = models.CharField(max_length=128)
    class_id = models.CharField(max_length=128)
    school_name = models.CharField(max_length=128)
    school_id = models.CharField(max_length=128)

class Marks(models.Model):
    exam_name = models.CharField(max_length=256)
    exam_id = models.CharField(max_length=256)
    subject_name = models.CharField(max_length=256)
    subject_id = models.CharField(max_length=256)
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    score = models.CharField(max_length=64)

class Permissions(models.Model):
    userid = models.CharField(max_length=128)
    can_get_data = models.BooleanField()
    is_admin = models.BooleanField()