from flask import Flask
app = Flask(__name__)

@app.route('/')
def ldap_connector():
    return 'Welcome To LDAP Connector'

@app.route('/ldap_config')
def ldap_config():
    ''' Configure connection to ldap server. Save data for reuse. '''
    return 'Configure LDAP'

@app.route('/tls_config')
def tls_config():
    ''' Configure connection to AWS API. Save data for reuse. '''
    return 'Configure TLS'

@app.route('/run_audit')
def run_audit():
    ''' Get ldap and aws accounts, create alerts from differences, send alerts to API. '''
    ldap = get_ldap_accounts()
    aws = get_aws_accounts()
    alerts = _compare_accounts(ldap, aws)
    send_alerts(alerts)
    return 'Running Audit'

def get_ldap_accounts():
    ''' Queries ldap server for list of current ldap users. '''
    return []

def get_aws_accounts():
    ''' Queries AWS iam service for list of current aws users. '''
    return []

def send_alerts(alerts):
    ''' Uses TLS connection to send alert messages to cloud API. '''
    pass

def _compare_accounts(ldap, aws):
    ''' Return alerts for accounts in AWS that are not in LDAP. '''
    return []
