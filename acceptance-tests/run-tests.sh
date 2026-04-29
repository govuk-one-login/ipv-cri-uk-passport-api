#!/usr/bin/env bash

set -e

export BROWSER="${BROWSER:-chrome-headless}"
export NO_CHROME_SANDBOX=true


# Added to accommodate ssm stack
if [[ -z "${CFN_StackName}" ]]; then
  if [[ -z "${SAM_STACK_NAME}" ]]; then
    export STACK_NAME="local"
  else
    export STACK_NAME="${SAM_STACK_NAME}"
  fi
else
  export STACK_NAME="${CFN_StackName}"
fi

# Added to accommodate ssm stack
if [[ -z "${ENVIRONMENT}" ]]; then
  if [[ -z "${TEST_ENVIRONMENT}" ]]; then
    export ENVIRONMENT="build"
  else
    export ENVIRONMENT="${TEST_ENVIRONMENT}"
  fi
else
  export ENVIRONMENT="${ENVIRONMENT}"
fi

echo "ENVIRONMENT ${ENVIRONMENT}"
echo "STACK_NAME ${STACK_NAME}"

TRAFFIC_TEST="${TRAFFIC_TEST:-false}"
TEST_RUNS=1 # default is 1 for the ac tests
CUCUMBER_SSM_PARAMETER="TestTag"
if [ "$TRAFFIC_TEST" = "true" ]; then
  # Passport CRI -
  # For a 5min lambda canary test to be meaningful the @traffic test suite
  # needs to match the length of the stack deploy duration.
  #
  # With @traffic tagged tests hitting all the journey lambdas.
  # The traffic test is triggered at the start of the deployment,
  # with the lambda canary period some time latter during the stack update.
  # It must not run beyond the stack deploy duration,
  # or will be running at the same time as the AC test suite.
  # Leading to the smaller dev F.E containers getting overwhelmed.
  TEST_RUNS=$(aws ssm get-parameter --name "/tests/$STACK_NAME/TrafficTestRuns" --region eu-west-2 | jq -r '.Parameter.Value')
  CUCUMBER_SSM_PARAMETER="TrafficTestTag"
  echo "Traffic Test selected with ${TEST_RUNS} iterations"
fi

REPORT_DIR="${TEST_REPORT_DIR:=$PWD}"

if [ "${STACK_NAME}" != "local" ]; then
  export JOURNEY_TAG=$(aws ssm get-parameter --name "/tests/${STACK_NAME}/${CUCUMBER_SSM_PARAMETER}" | jq -r ".Parameter.Value")

  PARAMETERS_NAMES=(coreStubPassword coreStubUrl coreStubUsername passportCriUrl apiBaseUrl orchestratorStubUrl API_GATEWAY_ID_PUBLIC)
  tLen=${#PARAMETERS_NAMES[@]}
   for (( i=0; i<${tLen}; i++ ));
  do
    echo "/tests/$STACK_NAME/${PARAMETERS_NAMES[$i]}"
    PARAMETER=$(aws ssm get-parameter --name "/tests/$STACK_NAME/${PARAMETERS_NAMES[$i]}" --region eu-west-2)
    VALUE=$(echo "$PARAMETER" | jq '.Parameter.Value')
    NAME=$(echo "$PARAMETER" | jq '.Parameter.Name' | cut -d "/" -f4 | sed 's/.$//')

    eval $(echo "export ${NAME}=${VALUE}")
  done
else
  export JOURNEY_TAG="${TEST_TAG}"
fi

echo "Cucumber Journey Tags being used: ${JOURNEY_TAG}"

pushd /home/gradle/cri/acceptance-tests
for (( i=1; i<=TEST_RUNS; i++ )); do
  if [ "$TEST_RUNS" -gt 1 ]; then
    echo "Test run ${i} of ${TEST_RUNS}"
  fi
  gradle cucumber --no-watch-fs -P tags="${JOURNEY_TAG}"
done
popd

if [ "$TRAFFIC_TEST" = false ]; then
  cp -r /home/gradle/cri/acceptance-tests/build/test-results "$REPORT_DIR"
fi
