from django.http import HttpResponseBadRequest
from django.shortcuts import render, HttpResponseRedirect
from google_auth_oauthlib.flow import Flow
from oauth2client.contrib.django_util.storage import DjangoORMStorage
from googleapiclient.discovery import build
import httplib2
import secrets
from g_auth.models import *
from django.conf import settings

# Create your views here

FLOW = Flow.from_client_secrets_file(
    settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON,
    scopes=['https://www.googleapis.com/auth/gmail.readonly'],
    redirect_uri='http://127.0.0.1:8000/oauth2callback',
)

csrf_token = secrets.token_urlsafe()

def gmail_authenticate(request):
    
    request.session['csrf_token'] = csrf_token

    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    credential = storage.get()
    if credential is None or credential.invalid:

        authorization_url, state = FLOW.authorization_url(access_type='offline', include_granted_scopes='true')
        request.session['state'] = state
        return HttpResponseRedirect(authorization_url)
    
    else:
    
        http = httplib2.Http()
        http = credential.authorize(http)
        service = build('gmail', 'v1', http=http)
        print('access_token = ', credential.access_token)
        status = True

        return render(request, 'index.html', {'status': status})


def auth_return(request):

    get_state = request.GET.get('state')
    session_state = request.session.get('state')

    if not get_state or get_state != session_state:
        return HttpResponseBadRequest("Invalid state parameter")

    credential = FLOW.fetch_token(
        authorization_response=request.build_absolute_uri(),
        client_secret= None
    )

    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    storage.put(credential)

    print("access_token: %s" % credential.access_token)
    
    return HttpResponseRedirect("/")

def home(request):
    status = True
 
    if not request.user.is_authenticated:
        return HttpResponseRedirect('admin')
 
    storage = DjangoORMStorage(CredentialsModel, 'id', request.user, 'credential')
    credential = storage.get()
 
    try:
        access_token = credential.access_token
        resp, cont = httplib2.Http().request("https://www.googleapis.com/auth/gmail.readonly",
                                     headers ={'Host': 'www.googleapis.com',
                                             'Authorization': access_token})
    except:
        status = False
        print('Not Found')
 
    return render(request, 'index.html', {'status': status})
