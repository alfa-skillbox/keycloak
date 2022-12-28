#!/usr/bin/env bash
set -ex

###########################
#- VARS
###########################
KEYCLOAK=keycloak
KEYCLOAK_KEY_PASSWORD=keycloak-password
KEYCLOAK_KEYSTORE_PASSWORD=keycloak-password
KEYCLOAK_KEYSTORE_ALIAS=keycloak-local
###########################
#--- DOCKER IMPORT VARS
###########################
PATH_TO_IMPORT=./imports/$KEYCLOAK
PATH_TO_RESOURCES=src/main/resources
AUTH_CODE_CLIENT_RESOURCES=../authorization-code-client/$PATH_TO_RESOURCES
CC_CLIENT_RESOURCES=../client-credentials-client/$PATH_TO_RESOURCES
RESOURCE_SERVER_RESOURCES=../resource-server/$PATH_TO_RESOURCES

# Generates keypair (private key + public key wrapped in self-signed cert)
# This cert and the private key are stored in a new keystore entry identified by alias
keytool -keystore $KEYCLOAK.keystore \
        -storepass $KEYCLOAK_KEYSTORE_PASSWORD \
        -alias $KEYCLOAK_KEYSTORE_ALIAS \
        -dname "cn=localhost, ou=$KEYCLOAK-OU, o=$KEYCLOAK-O, c=$KEYCLOAK-C" \
        -ext bc:c \
        -storetype JKS \
        -keyalg RSA -validity 825 \
        -keypass $KEYCLOAK_KEY_PASSWORD \
        -genkeypair -v
#keytool -list -v -keystore keycloak.keystore -storepass keycloak-password -alias keycloak-local

# Exports self-signed keycloak-client .pem certificate
keytool -keystore $KEYCLOAK.keystore \
        -storepass $KEYCLOAK_KEYSTORE_PASSWORD \
        -alias $KEYCLOAK_KEYSTORE_ALIAS \
        -exportcert \
        -rfc -file $KEYCLOAK.crt

# convert jks to p12
keytool -importkeystore \
      -srckeystore $KEYCLOAK.keystore \
      -srcstorepass $KEYCLOAK_KEYSTORE_PASSWORD \
      -srcalias $KEYCLOAK_KEYSTORE_ALIAS \
      -destkeystore $KEYCLOAK.p12 \
      -deststoretype PKCS12 \
      -destalias $KEYCLOAK_KEYSTORE_ALIAS \
      -deststorepass $KEYCLOAK_KEYSTORE_PASSWORD \
      -destkeypass $KEYCLOAK_KEY_PASSWORD

# export private key and cert using openssl
openssl pkcs12 -in $KEYCLOAK.p12 -noenc -nocerts -out $KEYCLOAK.key -password pass:$KEYCLOAK_KEYSTORE_PASSWORD
openssl pkcs12 -in $KEYCLOAK.p12 -noenc -nokeys -out $KEYCLOAK.crt -password pass:$KEYCLOAK_KEYSTORE_PASSWORD

# import cert to local truststore
keytool -importcert -noprompt -alias $KEYCLOAK_KEYSTORE_ALIAS -file $KEYCLOAK.crt -keystore $KEYCLOAK.truststore -storepass $KEYCLOAK_KEYSTORE_PASSWORD -storetype JKS
########################################
# Copies result to docker import
########################################
cp $KEYCLOAK.key $PATH_TO_IMPORT/tls.key
cp $KEYCLOAK.crt $PATH_TO_IMPORT/tls.crt
cp $KEYCLOAK.truststore $AUTH_CODE_CLIENT_RESOURCES/$KEYCLOAK.truststore
cp $KEYCLOAK.truststore $CC_CLIENT_RESOURCES/$KEYCLOAK.truststore
cp $KEYCLOAK.truststore $RESOURCE_SERVER_RESOURCES/$KEYCLOAK.truststore

rm -f $KEYCLOAK.key
rm -f $KEYCLOAK.crt
rm -f $KEYCLOAK.keystore
rm -f $KEYCLOAK.p12
rm -f $KEYCLOAK.truststore
########################################
# Changes modification of copied files
########################################
chmod 655 $PATH_TO_IMPORT/tls.key
chmod 655 $PATH_TO_IMPORT/tls.crt