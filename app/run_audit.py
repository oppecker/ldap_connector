import json
import ldap
import os
import requests

class LDAPConnector():
    def __init__(self):
        self.ldap_ip = os.environ['LDAP_IP']
        self.ldap_admin = os.environ['LDAP_ADMIN']
        self.ldap_admin_pw = os.environ['LDAP_ADMIN_PW']
        self.expiire_url = os.environ['EXPIIRE_URL']
        self.expiire_company_id = os.environ['EXPIIRE_COMPANY_ID']
        self.expiire_pw =  os.environ['EXPIIRE_PW']

        self.headers = {'Content-Type': 'application/javascript'}


    def run_audit(self):
        ''' Get ldap and aws accounts, create alerts from differences, send alerts to API. '''
        ldap_users = self.get_ldap_users()
        print(ldap_users)
        cloud_users = self.get_cloud_users()
        print(cloud_users)
        sus_users = self._compare_accounts(ldap_users, cloud_users)
        print(sus_users)
        alert_ids = self.send_alerts(sus_users)
        return f"Created Alerts: {alert_ids}"

    def get_ldap_users(self):
        ''' Queries ldap server for list of current ldap users. '''
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        connect = ldap.initialize(f"ldap://{self.ldap_ip}")
        connect.simple_bind_s(self.ldap_admin, self.ldap_admin_pw)
        return connect.search_s(
            'dc=example,dc=com',
            ldap.SCOPE_SUBTREE,
            'objectClass=*',
        )

    def get_cloud_users(self):
        ''' Queries EXPIIRE service for list of users. '''
        self.set_expiire_auth()
        url = f"{self.expiire_url}/clouduser?company_id={self.expiire_company_id}"
        r = requests.get(url, headers=self.headers)
        self._debug_request(r)
        return json.loads(r.text)

    def _compare_accounts(self, ldap_users, cloud_users):
        ''' Return usernames for accounts in EXPIIRE that are not in LDAP. '''
        ldap_names = []
        for user in ldap_users:
            if user[1].get('uid'):
                ldap_names.append(user[1]['uid'][1].decode())

        current_alerts = []
        for alert in self.get_all_alerts_per_company(self.expiire_company_id):
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

    def send_alerts(self, sus_users):
        ''' Uses TLS connection to send alert messages to cloud API. '''
        alert_ids = []
        for user in sus_users:
            alert_id = self.create_alert(
                company_id = self.expiire_company_id,
                account_id = user['account_id'],
                user_id = user['user_id'],
                account_number = user['account_number'],
                iam_user_name = user['name'],
            )
            alert_ids.append(alert_id)
        return alert_ids

    def _debug_request(self, r):
        if 1:
            print(r.status_code)
            print(r.text)
            print(r.reason)
            r.raise_for_status()

    def set_expiire_auth(self):
        ''' Configure connection to EXPIIRE API. Save data for reuse. '''
        url = f"{self.expiire_url}/expiireuser/login"
        data = {
            'user_name': f"LdapAgent_{self.expiire_company_id}",
            'password': self.expiire_pw,
        }
        r = requests.post(url, headers=self.headers, data=json.dumps(data))
        self._debug_request(r)

        token = json.loads(r.text)['access_token']
        self.headers['Authorization'] = f"Bearer {token}"

    def get_all_alerts_per_company(self, company_id):
        url = f"{self.expiire_url}/alert?company_id={self.expiire_company_id}"
        r = requests.get(url, headers=self.headers)
        self._debug_request(r)
        return json.loads(r.text)

    def create_alert(
        self,
        company_id, 
        account_id, 
        user_id,
        account_number, 
        iam_user_name, 
        cloud_service="AWS", 
        alert_status="New",
    ):

        self.set_expiire_auth()
        url = f"{self.expiire_url}/alert"
        alert_data = {
            "company_id" : company_id,
            "account_id" : account_id,
            "account_number" : account_number,
            "iam_user_name" : iam_user_name,
            "cloud_service" : cloud_service,
            "alert_status" : alert_status,
            "user_id": user_id,
        }

        r = requests.post(url, headers=self.headers, data=json.dumps(alert_data))
        self._debug_request(r)
        return json.loads(r.text)["alert_id"]

if __name__ == '__main__':
    
    ldap_connector = LDAPConnector()
    alert_ids = ldap_connector.run_audit()
    print(alert_ids)
