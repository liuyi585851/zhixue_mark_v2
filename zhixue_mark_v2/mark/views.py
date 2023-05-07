from django.shortcuts import render,HttpResponse,redirect
from django.core.exceptions import BadRequest
from .zhixuescoreapi import login
import json
import uuid
import datetime
from .models import ApiLogs,LoginLogs,Permissions,Marks
# ------常量定义------
TEACHER_ACCOUNT = "zxt573338"
TEACHER_PASSWORD = "111111"
# -------------------

# ------Api Handlers 后端api函数------
zhixueapi = login(TEACHER_ACCOUNT,TEACHER_PASSWORD) #初始化api
zhixueapi.update_login_status() #刷新登录状态

def student_info(request):
    username = request.GET.get("username",None)
    password = request.GET.get("password",None)
    if username and password:
        try:
            stu_session = login(username,password)
        except Exception as e:
            trace_id = api_logger(request,'USER_REQUEST','student_info','failed',str(e))
            content = {
                'status': 'failed',
                'trace_id': trace_id,
                'message': str(e)
            }
            return HttpResponse(json.dumps(content),status=400)
        trace_id = api_logger(request,'USER_REQUEST','student_info','success',stu_session)
        content = {
            'status': 'success',
            'trace_id': trace_id,
            'message': stu_session.info
        }
        return HttpResponse(json.dumps(content),status=200)
    else:
        trace_id = api_logger(request,'USER_REQUEST','student_info','failed','Params Missed')
        content = {
            'status': 'failed',
            'trace_id': trace_id,
            'message': 'Params Missed',
        }
        return HttpResponse(json.dumps(content),status=400)

def api_logger(request,log_type:str,action:str,status:str,message:str) -> str:
    '''
    api日志处理函数
    Args:
    log_type:(USER_REQUEST,SYSTEM_ERROR)
    action:操作名称
    status:返回状态
    message:返回信息
    
    Log Informations:
    trace_id 随机uuid
    request_time 请求时间
    request_url 请求url
    request_ip 来源ip
    request_method 请求方法
    log_type 操作类型
    action 操作名称
    status 返回状态
    message 返回信息
    '''
    trace_id = str(uuid.uuid4())
    request_time = str(datetime.datetime.now())
    request_url = request.path
    request_ip = request.META.get('REMOTE_ADDR')
    request_method = request.method
    log_type = log_type
    action = action
    status = status
    message = message
    try:
        ApiLogs.objects.create(trace_id=trace_id,request_time=request_time,request_url=request_url,request_ip=request_ip,request_method=request_method,log_type=log_type,action=action,status=status,message=message)
    except Exception as e: 
        raise e
    return trace_id

def login_logger(request,username:str,password:str,status:str,message:str) -> str:
    '''
    登录日志处理函数
    Args:
    username:用户名
    password:密码
    status:登录结果
    message:返回信息
    
    Log Informations:
    log_id 随机uuid
    login_time 登录时间
    login_from  来源ip
    username 登录账号
    password 登录密码
    status = 登录结果
    message = 返回信息
    '''
    log_id = str(uuid.uuid4())
    login_time = str(datetime.datetime.now())
    login_from = request.META.get('REMOTE_ADDR')
    status = status
    message = message
    try:
        LoginLogs.objects.create(log_id=log_id,login_time=login_time,login_from=login_from,status=status,message=message)
    except Exception as e:
        raise e
    return log_id

def login_page(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            username = data['username']
            password = data['password']
        except:
            return HttpResponse("非法请求")
        try:
            login(username,password)
        except Exception as e:
            return HttpResponse(e,status=400)
        request.session['is_login'] = True
        request.session['username'] = username
        request.session['password'] = password
        return HttpResponse('success')
    if request.session.get('is_login',None):
        return redirect('/index/')
    return render(request,'login.html',locals())

def temp_c(request):#22556741-1e16-4bfa-bb72-cbdd5bdd2a05
    #c = zhixueapi.get_simple_answer_records("9190939218000000093","aa324c2a-6256-4241-8db8-0d4396a149f4",67)
    c = zhixueapi.get_school_answer_records("4444000020000002817","aa324c2a-6256-4241-8db8-0d4396a149f4",22)
    print(c[0].keys())
    return HttpResponse(c)

def list_exam(request):
    stuapi = login("17074271","qwertyU8")
    print(stuapi.get_user_exam_list())
    return HttpResponse()

def get_exam_data(request):
    username = request.session.get("username",None)
    try:
        data = Permissions.objects.get(userid=username)
        if data.can_get_data:
            is_allowed = True
        else:
            is_allowed = False
    except:
        is_allowed = False
    if not is_allowed:
        return HttpResponse("您的权限不足")
    return HttpResponse("ok")

def index(request):
    if request.session.get('is_login',None):
        return render(request,'index.html',locals())
    else:
        return redirect('/login/')

def logout(request):
    request.session.flush()
    return redirect('/login/')

def adminboard(request):
    if request.session.get('is_login',None):
        data = Permissions.objects.get(userid=request.session.get('username'))
        if not data.is_admin:
            return redirect('/index/')
        return render(request,'adminboard.html',locals())
    else:
        return redirect('/login/')