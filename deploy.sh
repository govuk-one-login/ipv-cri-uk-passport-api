#!/usr/bin/env bash
set -e

CURRENT_PATH="${PWD}"

RED="\033[1;31m"
GREEN="\033[1;32m"
NOCOLOR="\033[0m"

stack_name="$1"
audit_event_name_prefix="$2"
cri_identifier="$3"

if [ -z "$stack_name" ]; then
  echo -e "😱 ${RED}stack name expected as first argument, e.g. ${GREEN}./deploy.sh my-ukpassport-api${NOCOLOR}"
  exit 1
fi

if [ -z "$audit_event_name_prefix" ]; then
  audit_event_name_prefix="/common-cri-parameters/PassportAuditEventNamePrefix"
fi

if [ -z "$cri_identifier" ]; then
  cri_identifier="/common-cri-parameters/PassportCriIdentifier"
fi

echo -e "👉 deploying di-ipv-cri-uk-passport-api with:"
echo -e "\tstack name: ${GREEN}$stack_name${NOCOLOR}"
echo -e "\tAuditEventNamePrefix SSM key ${GREEN}$audit_event_name_prefix${NOCOLOR}"
echo -e "\tCriIdentifier SSM key ${GREEN}$cri_identifier${NOCOLOR}"

echo -e "🧹 Starting a clean build"
./gradlew clean
echo -e "🔎 Checking with cfn-lint"
cfn-lint infrastructure/lambda/template.yaml -f pretty
echo -e "🔎 Checking with sam validate --lint"
sam validate -t infrastructure/lambda/template.yaml --config-env dev --lint
echo -e "🧱 Building with sam build"
sam build -s "$CURRENT_PATH" -t infrastructure/lambda/template.yaml --config-env dev
echo -e "🚀 Deploying..."
sam validate -t infrastructure/lambda/template.yaml --config-env dev --lint
sam build -s "$CURRENT_PATH" -t infrastructure/lambda/template.yaml --config-env dev
sam deploy --stack-name "$stack_name" \
  --no-fail-on-empty-changeset \
  --no-confirm-changeset \
  --resolve-s3 \
  --region eu-west-2 \
  --capabilities CAPABILITY_IAM \
  --tags \
  cri:component=ipv-cri-uk-passport-api \
  cri:stack-type=dev \
  cri:application=Lime \
  cri:deployment-source=manual \
  --parameter-overrides \
  CodeSigningEnabled=false \
  DevEnvironment="not-cri-dev" \
  Environment=dev \
  AuditEventNamePrefix=$audit_event_name_prefix \
  CommonStackName=passport-common-cri-api-local \
  CreateMockTxmaResourcesOverride=true \
  CriIdentifier=$cri_identifier \
  ParameterPrefix="ipv-cri-passport-api" \
  DeploymentType="not-pipeline"
