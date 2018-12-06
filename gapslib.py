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

from apiclient import errors
from apiclient.discovery import build

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand

from ConfigParser import SafeConfigParser
from oauth2client.client import SignedJwtAssertionCredentials

## Get confgiruation
config = SafeConfigParser()
config.read('/etc/gaps/gaps.conf')

## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

filename = config.get('common', 'path_password_file')
dict_mail_password={}
if os.path.isfile(filename):
    dict_mail_password = json.loads(open(filename,'r').read())

## Load Google Configuration ##
with open( config.get('google', 'service_json')) as data_file:
  gaConfig = json.load(data_file)

## Load Google Service ##
def createDirectoryService(user_email):
  credentials = SignedJwtAssertionCredentials(
        gaConfig['client_email'],
        gaConfig['private_key'],
        scope='https://www.googleapis.com/auth/admin.directory.user',
        sub=user_email
  )

  http = httplib2.Http()
  http = credentials.authorize(http)

  return build('admin', 'directory_v1', http=http)


def update_password(mail, pwd):
    # Create a new service object
    print mail
    print pwd
    service = createDirectoryService(config.get('google', 'admin_email'))

    try:
        user = service.users().get(userKey = mail).execute()
    except:
        syslog.syslog(syslog.LOG_WARNING, '[WARNING] Account %s not found' % mail)
        return 0

    user['hashFunction'] = 'crypt'
    user['password'] = password

    try:
        service.users().update(userKey = mail, body=user).execute()
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        dict_mail_password[str(user["mail"])]=str(password[passwordattr])
        open(filename,'w').write(json.dumps(dict_mail_password))
    except:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] Could not update password for %s ' % mail)
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
    filename ='dict_mail_password.json'
    testpawd = GetPasswordCommand()
    testpawd.lp = lp

    passwordattr = config.get('common', 'attr_password')
    for user in samdb_loc.search(base=param_samba['adbase'], expression="(&(objectClass=user)(mail=*))", attrs=["mail","sAMAccountName"]):
        mail = str(user["mail"])
        if config.get('common', 'replace_domain'):
            mail = mail.split('@')[0] + '@' + config.get('common', 'domain')

        password = testpawd.get_account_attributes(samdb_loc,None,param_samba['basedn'],filter="(sAMAccountName=%s)" % (str(user["sAMAccountName"])),scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=True)

        if passwordattr == 'unicodePwd':
            password = '$3$$' + str(password[passwordattr]).encode('hex')
        else:
            password = str(password[passwordattr])

        if str(password) != dict_mail_password.get(mail,''):
            update_password(mail, password)



