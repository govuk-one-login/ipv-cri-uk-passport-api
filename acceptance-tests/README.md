# di-ipv-cri-passport-test

This folder has be created as a central location for any work related to Passport CRI testing.

## Build

Build with `./gradlew`

### Run tests

When running locally the following environment variables must be set

ENVIRONMENT \
AWS_STACK_NAME \
API_GATEWAY_ID_PRIVATE \
apiBaseUrl \
coreStubUrl \
coreStubUsername \
coreStubPassword \
passportCriUrl  \
orchestratorStubUrl

Speak to a member of the test team for these values
When running in the pipeline these will be taken from AWS

Run tests with `./gradlew cucumber -P tags=@build`
or if its your first time running these tests `./run-local-tests.sh` will help you setup
and run the tests

Cucumber reports are available following pre-merge workflow execution for a PR.
Within the Run pre-merge integration tests step, a link will be created to download the zip file for the cucumber report.

When running the pre-merge tests locally a cucumber report will be generated in the `acceptance-tests/target/cucumber-report`
