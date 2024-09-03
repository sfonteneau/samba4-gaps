#!/usr/bin/env python
import sys
import hashlib
import json
import ldb
import os
import optparse
import hashlib
import pickle
import logging
import datetime
import json

logger = logging.getLogger()

try:
    from Cryptodome import Random
except ImportError:
    from Crypto import Random
    
from apiclient import errors
from apiclient.discovery import build

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
try:
    from samba.netcmd.user.readpasswords.common import GetPasswordCommand
except ImportError:
    from samba.netcmd.user import GetPasswordCommand
import samba.getopt as options


import configparser
from google.oauth2 import service_account
import googleapiclient.discovery
from googleapiclient.discovery import build

from peewee import SqliteDatabase,CharField,Model,TextField

## Get confgiruation
config = configparser.ConfigParser()
config.read('/etc/gaps/gaps.conf')

logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

logfile = config.get('common', 'logfile')
fhandler = logging.FileHandler(logfile)
logger.addHandler(fhandler)

db = SqliteDatabase(config.get('common', 'dbpath'))

def hash_for_data(data):
    return hashlib.sha1(pickle.dumps(data)).hexdigest()

class LastSend(Model):
    mail       = CharField(primary_key=True, index=True)
    sha1hashnt = CharField()

    class Meta:
        database = db

if not LastSend.table_exists():
    db.create_tables([LastSend])

## Load Google Configuration ##
with open( config.get('google', 'service_json')) as data_file:
  gaConfig = json.load(data_file)

ldap_filter = config.get('samba', 'ldap_filter')
mail_attribut = config.get('samba', 'mail_attribut')

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user']

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


def update_password(mail, pwd, sha1hashnt):
    # Create a new service object
    try:
        service = create_directory_service(config.get('google', 'admin_email'))
    except:
        logger.error(json.dumps({'status':"error",'msg':str(e),'timestamp': str(datetime.datetime.utcnow())}))
        return

    try:
        user = service.users().get(userKey = mail).execute()
    except:
        logger.warning(json.dumps({'status':"warning",'msg':'Account not found','timestamp': str(datetime.datetime.utcnow()),'mail':mail}))
        return 0

    try:
        #Change password
        userbody = { 'hashFunction': 'crypt','password': pwd.replace('{CRYPT}','')}
        request = service.users().update(userKey = mail, body = userbody)
        response = request.execute()

        LastSend.insert(mail=mail,sha1hashnt = sha1hashnt).on_conflict_replace().execute()
        logger.info(json.dumps({'status':"ok",'msg':'updated password','timestamp': str(datetime.datetime.utcnow()),'mail':mail}))
    except Exception as e:
        logger.error(json.dumps({'status':"error",'msg':str(e),'timestamp': str(datetime.datetime.utcnow()),'mail':mail}))
    finally:
        service = None

def run():


    if config.has_section('samba') and config.has_option('samba', 'smbconf'):
        smbconf = config.get('samba', 'smbconf')
    else:
        smbconf = "/etc/samba/smb.conf"

    if not smbconf:
        smbconf = "/etc/samba/smb.conf"

    parser = optparse.OptionParser(smbconf)
    sambaopts = options.SambaOptions(parser)

    # SAMDB
    lp = sambaopts.get_loadparm()

    creds = Credentials()
    creds.guess(lp)

    samdb_loc = SamDB(session_info=system_session(),credentials=creds, lp=lp)

    if config.has_option('samba', 'basedn') and config.get('samba', 'basedn'):
        adbase = config.get('samba', 'basedn')
    else:
        adbase = samdb_loc.get_default_basedn()

    testpawd = GetPasswordCommand()
    testpawd.lp = lp
    passwordattr = config.get('samba', 'attr_password')
    allmail = {}

    # Search all users

    for user in samdb_loc.search(base=adbase, expression=ldap_filter, attrs=[mail_attribut,"sAMAccountName","pwdLastSet"]):
        mail = user.get(mail_attribut,[b''])[0].decode('utf-8')
        password = testpawd.get_account_attributes(samdb_loc,None,adbase,filter="(sAMAccountName=%s)" % (str(user["sAMAccountName"])),scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
        if not passwordattr in password:
            continue
        password = str(password[passwordattr])
        shapassword = hash_for_data(password)
        Random.atfork()

        #replace mail if replace_domain in config
        if config.getboolean('common', 'replace_domain'):
            mail = mail.split('@')[0] + '@' + config.get('common', 'domain')


        #add mail in all mail
        allmail[mail] = None

        last_data = LastSend.select(LastSend.sha1hashnt).where(LastSend.mail==mail).first()
        if (not last_data) or shapassword != last_data.sha1hashnt:

            # Update if password different in dict mail pwdlastset
            update_password(mail, password,shapassword)

    for user in LastSend.select(LastSend.mail):
        if not user.mail in allmail:
            LastSend.delete().where(LastSend.mail==user.mail).execute()
