# Digital Identity Passport Credential Issuer

This the back-end code for V1 of the UK Passport Credential Issuer(CRI) for the Identity Proofing and Verification (IPV) system within the GDS digital identity platform, GOV.UK Sign In.

Passport API V1 was created as part of all CRI's standardizing on using [common-lambdas](https://github.com/alphagov/di-ipv-cri-common-lambdas) and [cri-lib](https://github.com/alphagov/di-ipv-cri-lib) for common processing steps and internal services.

## Pre-Commit Checking / Verification

Completely optional, there is a `.pre-commit-config.yaml` configuration setup in this repo, this uses [pre-commit](https://pre-commit.com/) to verify your commit before actually commiting, it runs the following checks:

* Check Json files for formatting issues
* Fixes end of file issues (it will auto correct if it spots an issue - you will need to run the git commit again after it has fixed the issue)
* It automatically removes trailing whitespaces (again will need to run commit again after it detects and fixes the issue)
* Detects aws credentials or private keys accidentally added to the repo
* runs cloud formation linter and detects issues
* runs checkov and checks for any issues.

### Dependency Installation
To use this locally you will first need to install the dependencies, this can be done in 2 ways:

#### Method 1 - Python pip

Run the following in a terminal:

```
sudo -H pip3 install checkov pre-commit cfn-lint
```

this should work across platforms

#### Method 2 - Brew

If you have brew installed please run the following:

```
brew install pre-commit ;\
brew install cfn-lint ;\
brew install checkov
```

### Post Installation Configuration
once installed run:
```
pre-commit install
```

To update the various versions of the pre-commit plugins, this can be done by running:

```
pre-commit autoupdate && pre-commit install
```

This will install / configure the pre-commit git hooks,  if it detects an issue while committing it will produce an output like the following:

```
 git commit -a
check json...........................................(no files to check)Skipped
fix end of files.........................................................Passed
trim trailing whitespace.................................................Passed
detect aws credentials...................................................Passed
detect private key.......................................................Passed
AWS CloudFormation Linter................................................Failed
- hook id: cfn-python-lint
- exit code: 4

W3011 Both UpdateReplacePolicy and DeletionPolicy are needed to protect Resources/PublicHostedZone from deletion
core/deploy/dns-zones/template.yaml:20:3

Checkov..............................................(no files to check)Skipped
- hook id: checkov
```

To remove the pre-commit hooks should there be an issue
```
pre-commit uninstall
```

## SDKMan
This project has an `.sdkmanrc` file

Install SDKMan via the instructions on `https://sdkman.io/install`

For auto-switching between JDK versions, edit your `~/.sdkman/etc/config` and set `sdkman_auto_env=true`

Then use sdkman to install Java JDK listed in this projects `.sdkmanrc`
e.g `sdk install java x.y.z-amzn`

Restart your terminal

## Gradle

Gradle 8 is used on this project

## Build

Build with `./gradlew`

By default, this also calls spotlessApply and runs unit tests

## Linting

Check with `./gradlew :spotlessCheck`

Apply with `./gradlew :spotlessApply`

## Coverage Reports

Generate with `./gradlew reports` placed in `build/reports`

## Deployment

### Prerequisites

See onboarding guide for instructions on how to setup the following command line interfaces (CLI)
- aws cli
- aws-vault
- sam cli

### Deploy to passport dev account

`aws-vault exec pa-dev -- ./deploy.sh ipv-cri-passport-MyUsernameOrTicketNumber`

### Delete stack from passport dev account
> The stack name *must* be unique to you and created by you in the deploy step above.
> Type `y`es when prompted to delete the stack and the folders in the S3 bucket

The command to run is:

`aws-vault exec pa-dev -- sam delete --stack-name ipv-cri-passport-MyUsernameOrTicketNumber`

### Parameter prefix

This allows a deploying stack to use parameters of another stack.
Created to enable pre-merge integration tests to use the parameters of the pipeline stack.

ParameterPrefix if set, this value is used in place of AWS::Stackname for parameter store paths.
- Default is "none", which will use AWS::StackName as the prefix.

Can also be used with the following limitations in development.
- Existing stack needs to have all the parameters needed for the stack with the prefix enabled.
- Existing stack parameters values if changed will trigger behaviour changes in the stack with the prefix enabled.
- Existing stack if deleted will cause errors in the deployed stack.

## Testing with self deployed stub
If testing against a self deployed stub in the passporta dev environment.
The domain used by the stubs lambda function url will need added to
- The dns firewall allowed domains list
- A new rule added to the network firewall suricata rules config
  This will enable your deployed stack to connect to your deployed stub.

## Acceptance Test

In a terminal, change into the acceptance test folder and execute

`./run-local-tests`

Then follow the on-screen prompts.

### Note

To run API tests locally you need
- A manually deployed api stack with the code (main or branch) that is to be tested.
- A locally running core-stub with a cri id configured for `passport-v1-cri-dev`.

Acceptance tests
- build/staging test can be run against the environments.
- Using a locally running stub and front, with a manually deployed api stack configured to match the environments.

## TestData Strategy

For testing purposes, this CRI has the ability to route users requests to either
a real 3rd Party UAT instance of the service OR route users requests to an internally
managed, stubbed version of the 3rd party service.

Routing for the above is dictated by the client ID sent to the CRI from IPVCore/stubs. For lower
environments there is an IPV core stub that is configured to for routing CRIs to 3rd party stubs and another
IPV core stub that is configured for routing CRIs to the 3rd party UAT environment.

For testing purposes if you wish to route to the stubbed version of the 3rd party then use the following
core stub URL - https://cri.core.stubs.account.gov.uk/
If you wish to route to the real 3rd partys UAT instance of the service use the following
core stub url - https://cri-3rdparty.core.stubs.account.gov.uk/

Additional details on these stubs can be found on this confluence page -
https://govukverify.atlassian.net/wiki/spaces/OJ/pages/3147333723/Stubs+for+testing+journeys
