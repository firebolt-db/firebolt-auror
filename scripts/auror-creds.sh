#!/usr/bin/env bash

CREDS=$(aws configure export-credentials)
namespace="firebolt-auror"
accountID="123456789123"
PASSWORD=$(aws ecr get-login-password --region us-east-1)

if [ -n "$CREDS" ]; then
  echo "Credentials found"
else
  echo "No credentials found"
  exit 1
fi

if [ -n "$PASSWORD" ]; then
  echo "Password found"
else 
  echo "No password found"
  exit 1
fi

kubectl create secret generic aws-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId') \
  --from-literal=AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey') \
  --from-literal=AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.SessionToken') \
  -n $namespace \
  --dry-run=client -o yaml > secret-aws.yaml

kubectl create secret docker-registry pullsecret --docker-server=${accountID}.dkr.ecr.us-east-1.amazonaws.com \
    --docker-username=AWS \
    --docker-password=$PASSWORD \
    --docker-email=no-reply@firebolt.io \
    --namespace=${namespace} \
    --dry-run=client -o yaml > secret-docker.yaml

openssl req -newkey rsa:2048 -nodes -keyout tlsAuror.key -x509 -days 365 -out tlsAuror.crt -subj "/CN=auror.firebolt-auror.svc" -addext "subjectAltName=DNS:auror.firebolt-auror.svc,DNS:auror.firebolt-auror.svc.local,DNS:auror.firebolt-auror.svc.cluster.local"
kubectl create secret tls auror-certificates --cert=tlsAuror.crt --key=tlsAuror.key -n ${namespace} --dry-run=client -o yaml > secret-auror.yaml

kubectl apply -f secret-auror.yaml -n ${namespace}
kubectl apply -f secret-aws.yaml -n ${namespace}
kubectl apply -f secret-docker.yaml -n ${namespace}

cat <<EOF > values.kind.yaml
certificate:
  enabled: false

validatingWebhook:
  enabled: false

serviceMonitor:
  enabled: false

env:
  enabled: false
  kind:
    enabled: true

cosign:
  publicKey: |
      -----BEGIN PUBLIC KEY-----
      <add public key here>
      -----END PUBLIC KEY-----
EOF