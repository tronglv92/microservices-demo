#!/bin/bash
# check-keycloak-server-started.sh

curlResult=$(curl -s -o /dev/null -I -w "%{http_code}" http://keycloak-authorization-server:8080/realms/microservices_realm)

echo "check-keycloak-server-started result status code:" "$curlResult"

while [[ ! $curlResult == "200" ]]; do
  >&2 echo "Keycloak server is not up yet!"
  echo "check-keycloak-server-started result status code:" "$curlResult"
  sleep 2
  curlResult=$(curl -s -o /dev/null -I -w "%{http_code}" http://keycloak-authorization-server:8080/realms/microservices_realm)
done

/cnb/process/web