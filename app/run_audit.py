import json
import ldap
import os
import requests
from itertools import chain

class LDAPConnector():
    def __init__(self):
        self.ldap_ip = os.environ['LDAP_IP']
        self.ldap_admin = os.environ['LDAP_ADMIN']
        self.ldap_admin_pw = os.environ['LDAP_ADMIN_PW']
        self.expiire_url = os.environ['EXPIIRE_URL']
        self.expiire_company_id = os.environ['EXPIIRE_COMPANY_ID']
        self.expiire_pw =  os.environ['EXPIIRE_PW']
        self.headers = {'Content-Type': 'application/javascript'}
        self.debug = False


    def run_audit(self):
        ''' Get ldap and aws accounts, create alerts from differences. '''
        sus_users = self._compare_accounts(
            ldap_users = self.get_ldap_users(),
            cloud_users = self.get_cloud_users(),
        )
        alert_ids = [alert_id for alert_id in self.generate_alerts(sus_users)]
        return f"Created Alerts: {alert_ids}"

    def generate_alerts(self, sus_users):
        for user in sus_users:
            yield self.create_alert(
                company_id = self.expiire_company_id,
                account_id = user['account_id'],
                user_id = user['user_id'],
                account_number = user['account_number'],
                iam_user_name = user['name'],
            )

    def get_ldap_users(self):
        ''' Queries ldap server for list of current users. '''
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        connect = ldap.initialize(f"ldap://{self.ldap_ip}")
        connect.simple_bind_s(self.ldap_admin, self.ldap_admin_pw)
        return connect.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, 'objectClass=*')

    def get_cloud_users(self):
        ''' Queries EXPIIRE service for list of users. '''
        self.set_expiire_auth()
        r = requests.get(
            url = f"{self.expiire_url}/clouduser?company_id={self.expiire_company_id}",
            headers = self.headers,
        )
        self._debug_request(r)
        return json.loads(r.text)

    def _compare_accounts(self, ldap_users, cloud_users):
        ''' Return usernames for accounts in EXPIIRE that are not in LDAP. '''
        ldap_names = [user[1]['uid'][1].decode() for user in ldap_users if user[1].get('uid')]
        current_alerts = [alert['iam_user_name'] for alert in self.get_all_alerts()]
        print(f"Current Alerts: {current_alerts}")
            
        for user in cloud_users:
            if user['name'] not in chain(ldap_names, current_alerts):
                yield sus_users.append({
                    'name': user['name'],
                    'user_id': user['user_id'],
                    'account_number': user['account_number'],
                    'account_id': user['account_id'],
                })

    def _debug_request(self, r):
        if self.debug:
            print(r.status_code)
            print(r.text)
            print(r.reason)
            r.raise_for_status()

    def set_expiire_auth(self):
        ''' Configure connection to EXPIIRE API. Save data for reuse. '''
        r = requests.post(
            url = f"{self.expiire_url}/expiireuser/login",
            headers = self.headers,
            data = json.dumps({
                'user_name': f"LdapAgent_{self.expiire_company_id}",
                'password': self.expiire_pw,
            }),
        )
        self._debug_request(r)
        self.headers['Authorization'] = f"Bearer {json.loads(r.text)['access_token']}"

    def get_all_alerts(self):
        r = requests.get(
            url = f"{self.expiire_url}/alert?company_id={self.expiire_company_id}",
            headers = self.headers
        )
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
        r = requests.post(
            url = f"{self.expiire_url}/alert",
            headers = self.headers,
            data = json.dumps({
                "company_id" : company_id,
                "account_id" : account_id,
                "account_number" : account_number,
                "iam_user_name" : iam_user_name,
                "cloud_service" : cloud_service,
                "alert_status" : alert_status,
                "user_id": user_id,
            })
        )
        self._debug_request(r)
        return json.loads(r.text)["alert_id"]

if __name__ == '__main__':
    print(LDAPConnector().run_audit())
