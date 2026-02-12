# Shared Resources

This directory contains shared configuration files that are copied to multiple subprojects during the build process. This ensures consistent configuration across all modules and simplifies maintenance by providing a single source of truth.

## Log4j2 Configuration

### log4j2.xml

Common Log4j2 configuration that uses CustomLambdaJsonLayout.json for structured logging.

### CustomLambdaJsonLayout.json

A custom JSON template layout based on AWS Powertools 2.9.0' default [LambdaJsonLayout.json](https://github.com/aws-powertools/powertools-lambda-java/blob/main/powertools-logging/powertools-logging-log4j/src/main/resources/LambdaJsonLayout.json) with the following modifications:

**Added:**
- `loggerName`: Displays the fully qualified logger name (e.g., `uk.gov.di.ipv.cri.passport.api.handler.PassportHandler`). This helps identify the exact source of log messages and avoids ambiguity when multiple classes share the same name.

CustomLambdaJsonLayout.json is being used to add `loggerName` to the output.
If Powertools AWS Powertools 2.9.0' default [LambdaJsonLayout.json](https://github.com/aws-powertools/powertools-lambda-java/blob/main/powertools-logging/powertools-logging-log4j/src/main/resources/LambdaJsonLayout.json) gains loggerName then it is not needed.

To switch back to LambdaJsonLayout.json perform the following in log4j2.xml
- in `<JsonTemplateLayout
eventTemplateUri="classpath:CustomLambdaJsonLayout.json" />` change `classpath:CustomLambdaJsonLayout.json` to `classpath:LambdaJsonLayout.json`
- Delete the `CustomLambdaJsonLayout.json` file from `shared-resources`
- In top level `build.gradle` remove `from rootProject.file('shared-resources/CustomLambdaJsonLayout.json')` so the deleted file is no longer part of the list of files to copy
- Leave the step that copies log4j2.xml
- Update this README
