import ldap
import os

from flask import Flask
from flask import request
app = Flask(__name__)

@app.route('/')
def ldap_agent():
    return 'Welcome To LDAP Connector'

@app.route('/ldap_config', methods = ['POST'])
def ldap_config():
    ''' Configure connection to ldap server. Save data for reuse. '''
    data = request.get_json()
    if 'LDAP_ADMIN' in data:
        os.environ['LDAP_ADMIN'] = data['LDAP_ADMIN']
    if 'LDAP_ADMIN_PW' in data:
        os.environ['LDAP_ADMIN_PW'] = data['LDAP_ADMIN_PW']
    if 'LDAP_IP' in data:
        os.environ['LDAP_IP'] = data['LDAP_IP']
    return str(data)

@app.route('/tls_config', methods = ['POST'])
def tls_config():
    ''' Configure connection to AWS API. Save data for reuse. '''
    data = request.get_json()
    if 'API_IP' in data:
        os.environ['API_IP'] = data['API_IP']
    if 'API_TOKEN' in data:
        os.environ['API_TOKEN'] = data['API_TOKEN']
    return str(data)

@app.route('/run_audit')
def run_audit():
    ''' Get ldap and aws accounts, create alerts from differences, send alerts to API. '''
    ldap = get_ldap_users()
    aws = get_aws_users()
    alerts = _compare_accounts(ldap, aws)
    send_alerts(alerts)
    return 'Running Audit'

@app.route('/get_users', methods = ['GET'])
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
    return str(result)

def get_aws_users():
    ''' Queries AWS iam service for list of current aws users. '''
    return []

def send_alerts(alerts):
    ''' Uses TLS connection to send alert messages to cloud API. '''
    pass

def _compare_accounts(ldap, aws):
    ''' Return alerts for accounts in AWS that are not in LDAP. '''
    return []
