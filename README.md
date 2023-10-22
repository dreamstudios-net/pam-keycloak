# keycloak_pam

## How to build this module
`gcc -shared -o pam_keycloak.so -fPIC -lpam -lcurl -w -O2 pam_keycloak.c`

## How to use it
Example file pam config in /etc/pam.d/keycloak
```
keycloak: |
    account required /lib/x86_64-linux-gnu/security/pam_keycloak.so
    auth required /lib/x86_64-linux-gnu/security/pam_keycloak.so https://<hostname>/realms/<realm>/protocol/openid-connect/token <client-id> <client-secret>
```