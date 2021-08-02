#!/usr/bin/env python
import binascii
import quopri
import sys
import textwrap
import hashlib
import syslog
import json
import httplib2
import ldb
import os

from Crypto import Random
from apiclient import errors
from apiclient.discovery import build

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand


import configparser
from google.oauth2 import service_account
import googleapiclient.discovery
from googleapiclient.discovery import build

## Get confgiruation
config = configparser.ConfigParser()
config.read('/etc/gaps/gaps.conf')

## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

filename = config.get('common', 'path_pwdlastset_file')
dict_mail_pwdlastset={}
if os.path.isfile(filename):
    dict_mail_pwdlastset = json.loads(open(filename,'r').read())

## Load Google Configuration ##
with open( config.get('google', 'service_json')) as data_file:
  gaConfig = json.load(data_file)

SCOPES = ['https://www.googleapis.com/auth/admin.directory.group',
        'https://www.googleapis.com/auth/admin.directory.user']

## Load Google Service ##
def create_directory_service(user_email):
    credentials = service_account.Credentials.from_service_account_file(config.get('google', 'service_json'), scopes=SCOPES)

    if credentials is None:
        print(" ---- BAD CREDENTIALS  ---- ")

    delegated_credentials = credentials.with_subject(config.get('google', 'admin_email'))

    """
        build('api_name', 'api_version', ...)
        https://developers.google.com/api-client-library/python/apis/
    """
    return build('admin', 'directory_v1', credentials=delegated_credentials)


def update_password(mail, pwd, pwdlastset):
    # Create a new service object
    service = create_directory_service(config.get('google', 'admin_email'))

    try:
        user = service.users().get(userKey = mail).execute()
    except:
        syslog.syslog(syslog.LOG_WARNING, '[WARNING] Account %s not found' % mail)
        return 0

    try:
        #Change password
        userbody = { 'hashFunction': 'crypt','password': pwd.replace('{CRYPT}','')}
        request = service.users().update(userKey = mail, body = userbody)
        response = request.execute()


        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        dict_mail_pwdlastset[str(mail)]=str(pwdlastset)
        open(filename,'w').write(json.dumps(dict_mail_pwdlastset))
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] %s : %s' % (mail,str(e)))
    finally:
        service = None

def run():

    param_samba = {
    'basedn' : config.get('samba', 'path'),
    'pathsamdb':'%s/sam.ldb' % config.get('samba', 'private'),
    'adbase': config.get('samba', 'base')
    }

    # SAMDB
    lp = LoadParm()
    creds = Credentials()
    creds.guess(lp)
    samdb_loc = SamDB(url=param_samba['pathsamdb'], session_info=system_session(),credentials=creds, lp=lp)
    testpawd = GetPasswordCommand()
    testpawd.lp = lp
    passwordattr = config.get('common', 'attr_password')
    allmail = {}

    # Search all users
    for user in samdb_loc.search(base=param_samba['adbase'], expression="(&(objectClass=user)(mail=*))", attrs=["mail","sAMAccountName","pwdLastSet"]):
        mail = str(user["mail"])

        #replace mail if replace_domain in config
        if config.getboolean('common', 'replace_domain'):
            mail = mail.split('@')[0] + '@' + config.get('common', 'domain')

        pwdlastset = user.get('pwdLastSet','')

        #add mail in all mail
        allmail[mail] = None

        if str(pwdlastset) != dict_mail_pwdlastset.get(mail,''):

            Random.atfork()

            # Update if password different in dict mail pwdlastset
            password = testpawd.get_account_attributes(samdb_loc,None,param_samba['basedn'],filter="(sAMAccountName=%s)" % (str(user["sAMAccountName"])),scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
            if not passwordattr in password:
                continue
            password = str(password[passwordattr])
            update_password(mail, password, pwdlastset)

    #delete user found in dict mail pwdlastset but not found in samba
    listdelete = []
    for user in dict_mail_pwdlastset :
        if not user in allmail:
            listdelete.append(user)

    for user in listdelete:
        del dict_mail_pwdlastset[user]

    #write new json dict mail password
    if listdelete:
        open(filename,'w').write(json.dumps(dict_mail_pwdlastset))



