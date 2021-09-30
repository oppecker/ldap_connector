import json
import ldap
import os
import requests

def run_audit():
    ''' Get ldap and aws accounts, create alerts from differences, send alerts to API. '''
    ldap_users = get_ldap_users()
    print(ldap_users)
    cloud_users = get_cloud_users()
    print(cloud_users)
    sus_users = _compare_accounts(ldap_users, cloud_users)
    print(sus_users)
    alert_ids = send_alerts(sus_users)
    return f"Created Alerts: {alert_ids}"

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
    return result

def get_cloud_users():
    ''' Queries EXPIIRE service for list of users. '''
    set_expiire_auth()
    url = f"{os.environ['EXPIIRE_URL']}/clouduser?company_id={os.environ['EXPIIRE_COMPANY_ID']}"

    headers = {
        'Content-Type': 'application/javascript',
        'Authorization': os.environ['EXPIIRE_AUTH'],
    }
    r = requests.get(url, headers=headers)
    _debug_request(r)
    return json.loads(r.text)

def _compare_accounts(ldap_users, cloud_users):
    ''' Return usernames for accounts in EXPIIRE that are not in LDAP. '''
    ldap_names = []
    for user in ldap_users:
        if user[1].get('uid'):
            ldap_names.append(user[1]['uid'][1].decode())

    current_alerts = []
    for alert in get_all_alerts_per_company(os.environ['EXPIIRE_COMPANY_ID']):
        current_alerts.append(alert['iam_user_name'])
    print(f"CURRENT ALERTS: {current_alerts}")
        
    user_alerts = []
    for user in cloud_users:
        if user['name'] not in ldap_names:
            if user['name'] not in current_alerts:
                user_alerts.append({
                    'name': user['name'],
                    'user_id': user['user_id'],
                    'account_number': user['account_number'],
                    'account_id': user['account_id'],
                })
    return user_alerts

def send_alerts(sus_users):
    ''' Uses TLS connection to send alert messages to cloud API. '''
    alert_ids = []
    for user in sus_users:
        alert_id = create_alert(
            company_id = os.environ['EXPIIRE_COMPANY_ID'],
            account_id = user['account_id'],
            user_id = user['user_id'],
            account_number = user['account_number'],
            iam_user_name = user['name'],
        )
        alert_ids.append(alert_id)
    return alert_ids

def _debug_request(r):
    if 1:
        print(r.status_code)
        print(r.text)
        print(r.reason)
        r.raise_for_status()
def set_expiire_auth():
    ''' Configure connection to EXPIIRE API. Save data for reuse. '''
    url = f"{os.environ['EXPIIRE_URL']}/expiireuser/login"
    headers = {
        'Content-Type': 'application/javascript',
    }
    data = {
        'user_name': f"LdapAgent_{os.environ['EXPIIRE_COMPANY_ID']}",
        'password': os.environ['EXPIIRE_PW'],
    }
    r = requests.post(url, headers=headers, data=json.dumps(data))
    _debug_request(r)

    token = json.loads(r.text)['access_token']
    os.environ['EXPIIRE_AUTH'] = f"Bearer {token}"
    return os.environ['EXPIIRE_AUTH']

def get_all_alerts_per_company(company_id):
    url = f"{os.environ['EXPIIRE_URL']}/alert?company_id={os.environ['EXPIIRE_COMPANY_ID']}"
    headers = {
        'Content-Type': 'application/javascript',
        'Authorization': os.environ['EXPIIRE_AUTH'],
    }
    r = requests.get(url, headers=headers)
    _debug_request(r)
    return json.loads(r.text)

def create_alert(
    company_id, 
    account_id, 
    user_id,
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
        "user_id": user_id,
    }

    r = requests.post(url, headers=headers, data=json.dumps(alert_data))
    _debug_request(r)
    return json.loads(r.text)["alert_id"]

if __name__ == '__main__':
    alert_ids = run_audit()
    print(alert_ids)
