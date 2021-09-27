import json
import ldap
import os
import requests

from flask import Flask
from flask import request
app = Flask(__name__)

@app.route('/')
def ldap_agent():
    return 'Welcome To LDAP Connector'

@app.route('/config', methods = ['POST'])
def config():
    ''' Configure connection to ldap server. Save data for reuse. '''
    data = request.get_json()
    configurables = [
        'LDAP_ADMIN','LDAP_ADMIN_PW','LDAP_IP',
        'EXPIIRE_URL','EXPIIRE_USER','EXPIIRE_PW','EXPIIRE_COMPANY_ID',
    ]
    for key, value in data.items():
        if key in configurables:
            os.environ[key] = value
        
@app.route('/set_expiire_auth', methods = ['GET'])
def set_expiire_auth():
    ''' Configure connection to EXPIIRE API. Save data for reuse. '''
    url = f"{os.environ['EXPIIRE_URL']}/expiireuser/login"
    headers = {
        'Content-Type': 'application/javascript',
    }
    data = {
        'user_name': os.environ['EXPIIRE_USER'],
        'password': os.environ['EXPIIRE_PW'],
    }
    r = requests.post(url, headers=headers, data=json.dumps(data))
    _debug_request(r)

    token = json.loads(r.text)['access_token']
    os.environ['EXPIIRE_AUTH'] = f"Bearer {token}"

@app.route('/run_audit')
def run_audit():
    ''' Get ldap and aws accounts, create alerts from differences, send alerts to API. '''
    ldap_users = get_ldap_users()
    cloud_users = get_cloud_users()
    usernames = _compare_accounts(ldap_users, cloud_users)
    alert_ids = send_alerts(usernames)
    return f"Created Alerts: {alert_ids}"

@app.route('/get_ldap_users', methods = ['GET'])
def get_ldap_users():
    ''' Queries ldap server for list of current ldap users. '''
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    connect = ldap.initialize(f"ldap://{os.environ['LDAP_IP']}")
    connect.simple_bind_s(os.environ['LDAP_ADMIN'], os.environ['LDAP_ADMIN_PW'])
    result = connect.search_s(
        'dc=example,dc=com',
        ldap.SCOPE_SUBTREE,
        'objectClass=*',
    )
    return json.dumps(str(result))

@app.route('/get_cloud_users', methods = ['GET'])
def get_cloud_users():
    ''' Queries EXPIIRE service for list of users. '''
    set_expiire_auth()
    url = f"{os.environ['EXPIIRE_URL']}/clouduser?company_id={os.environ[EXPIIRE_COMPANY_ID]}"

    headers = {
        'Content-Type': 'application/javascript',
        'Authorization': os.environ['EXPIIRE_AUTH'],
    }
    r = requests.get(url, headers=headers)
    _debug_request(r)
    return json.loads(r.text)

def send_alerts(usernames):
    ''' Uses TLS connection to send alert messages to cloud API. '''
    alert_ids = []
    for user in usernames:
        alert_id = create_alert(
            company_id = os.environ['EXPIIRE_COMPANY_ID'],
            account_id = os.environ['EXPIIRE_ACCOUNT_ID'],
            account_number = os.environ['EXPIIRE_ACCOUNT_NUMBER'],
            iam_user_name = user,
        )
        alert_ids.append(alert_id)
    return alert_ids

def _compare_accounts(ldap_users, cloud_users):
    ''' Return usernames for accounts in EXPIIRE that are not in LDAP. '''
    #TODO: MAKE REAL NOT PSEUDOCODE
    usernames = []
    for user in cloud_users:
        if user not in ldap_users:
            user_alerts.append(user)
    return usernames

def _debug_request(r):
    if 1:
        print(r.status_code)
        print(r.text)
        print(r.reason)
        r.raise_for_status()

def create_alert(
    company_id, 
    account_id, 
    account_number, 
    iam_user_name, 
    cloud_service="AWS", 
    alert_status="New",
):

    set_expiire_auth()
    url = f"{os.environ['EXPIIRE_URL']}/alert"
    headers = {
        'Content-Type': 'application/javascript',
        'Authorization': os.environ['EXPIIRE_AUTH'],
    }
    alert_data = {
        "company_id" : company_id,
        "account_id" : account_id,
        "account_number" : account_number,
        "iam_user_name" : iam_user_name,
        "cloud_service" : cloud_service,
        "alert_status" : alert_status,
    }

    r = requests.post(url, headers=headers, data=json.dumps(alert_data))
    _debug_request(r)
    return json.loads(r.text)["alert_id"]

