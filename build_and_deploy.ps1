docker build --tag ldap_connector .
docker run -d -p 5000:5000 --name connector_server ldap_connector
