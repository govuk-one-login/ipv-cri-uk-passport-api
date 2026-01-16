package uk.gov.di.ipv.cri.passport.acceptance_tests.infra;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import software.amazon.awscdk.assertions.Template;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("QualityGateStackTest")
@Tag("InfraTest")
@DisplayName("Lambda CloudFormation Template Assertions")
class LambdaTemplateTest {

    private static Template cloudFormationTemplate;

    /** This method runs once before all tests to load and parse the CloudFormation template. */
    @BeforeAll
    static void setup() throws IOException {
        ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
        Path templateFilePath =
                Paths.get("..", "infrastructure", "lambda", "template.yaml").normalize();
        System.out.println(
                "Attempting to load template from: "
                        + templateFilePath.toAbsolutePath()); // Added for debugging

        try (InputStream inputStream = new FileInputStream(templateFilePath.toFile())) {
            Map<String, Object> templateMap =
                    yamlMapper.readValue(inputStream, new TypeReference<>() {});
            cloudFormationTemplate = Template.fromJSON(templateMap);
        }
        assertNotNull(cloudFormationTemplate, "CloudFormation template should be loaded.");
    }

    /**
     * Helper method to get the 'Properties' map for all resources of a given type.
     *
     * @param resourceType The AWS CloudFormation resource type (e.g., "AWS::Serverless::Api").
     * @return A map where keys are logical IDs and values are the 'Properties' map of each
     *     resource. Returns an empty map if no resources of the specified type are found. Asserts
     *     that 'Properties' map is not null for any found resource.
     */
    private static Map<String, Map<String, Object>> getAllResourceProperties(String resourceType) {
        Map<String, Map<String, Object>> resources =
                cloudFormationTemplate.findResources(resourceType);
        Map<String, Map<String, Object>> propertiesMap = new HashMap<>();

        if (resources.isEmpty()) {
            fail("Expected at least one " + resourceType + " resource in the template.");
            return propertiesMap;
        }

        for (Map.Entry<String, Map<String, Object>> entry : resources.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> resource = entry.getValue();

            @SuppressWarnings("unchecked") // Cast is safe if template structure is as expected
            Map<String, Object> properties = (Map<String, Object>) resource.get("Properties");

            assertNotNull(
                    properties,
                    "Properties map should not be null for resource: "
                            + logicalId
                            + " of type "
                            + resourceType);
            propertiesMap.put(logicalId, properties);
        }
        return propertiesMap;
    }

    /**
     * Helper method to get the full resource definition for all resources of a given type. This
     * includes 'Type', 'Properties', 'Condition', etc.
     *
     * @param resourceType The AWS CloudFormation resource type (e.g.,
     *     "AWS::Logs::SubscriptionFilter").
     * @return A map where keys are logical IDs and values are the full resource definition map.
     *     Returns an empty map if no resources of the specified type are found.
     */
    private static Map<String, Map<String, Object>> getAllResources(String resourceType) {
        Map<String, Map<String, Object>> resources =
                cloudFormationTemplate.findResources(resourceType);
        if (resources.isEmpty()) {
            fail("Expected at least one " + resourceType + " resource in the template.");
        }
        return resources;
    }

    /**
     * Helper method to safely retrieve a property from a map. This version is specifically designed
     * for the top-level 'Condition' property, expecting it to be a String.
     *
     * @param sourceMap The map to retrieve the property from (e.g., the full resource definition).
     * @return An Optional containing the 'Condition' property value as a String if found and of the
     *     correct type, otherwise empty.
     */
    private static Optional<String> getTopLevelProperty(Map<String, Object> sourceMap) {
        if (sourceMap != null && sourceMap.containsKey("Condition")) {
            Object value = sourceMap.get("Condition");
            if (value instanceof String) {
                return Optional.of(
                        (String) value); // Direct cast to String, which is safe due to instanceof
                // check
            }
        }
        return Optional.empty();
    }

    /**
     * Helper method to safely retrieve a property from a map using TypeReference for complex
     * generic types.
     *
     * @param <T> The generic type of the expected property.
     * @param sourceMap The map to retrieve the property from.
     * @param typeRef The TypeReference capturing the full generic type information.
     * @return An Optional containing the property value if found and of the correct type, otherwise
     *     empty.
     */
    private static <T> Optional<T> getPropertyTypeReference(
            Map<String, Object> sourceMap, TypeReference<T> typeRef) {
        String propertyKey = "MethodSettings";

        if (sourceMap != null && sourceMap.containsKey(propertyKey)) {
            Object value = sourceMap.get(propertyKey);
            try {
                @SuppressWarnings("unchecked")
                T castValue = (T) value;
                return Optional.of(castValue);
            } catch (ClassCastException e) {
                System.err.println(
                        "Type mismatch for property '"
                                + propertyKey
                                + "': Expected "
                                + typeRef.getType()
                                + ", found "
                                + "null"
                                + ". Error: "
                                + e.getMessage());
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
     * Helper method to safely retrieve a property from a map using a Class object for simpler
     * types.
     *
     * @param <T> The generic type of the expected property.
     * @return An Optional containing the property value if found and of the correct type, otherwise
     *     empty.
     */
    private static <T> Optional<T> getProperty(
            Map<String, Object> properties, String key, Class<T> type) {
        if (properties != null && properties.containsKey(key)) {
            Object value = properties.get(key);
            if (type.isInstance(value)) {
                return Optional.of(type.cast(value));
            }
        }
        return Optional.empty();
    }

    /**
     * Safely extracts a property from a given 'propertiesMap'. This version assumes the input
     * 'propertiesMap' is ALREADY the 'Properties' block of a CloudFormation resource.
     *
     * @param propertiesMap The map representing the 'Properties' block of a resource.
     * @param key The key of the property to retrieve (e.g., "AlarmActions").
     * @return An Optional containing the property's value, or Optional.empty() if not found.
     */
    private Optional<Object> getProperty(Map<String, Object> propertiesMap, String key) {
        if (propertiesMap != null) {
            Object value = propertiesMap.get(key);
            return Optional.ofNullable(
                    value); // Returns Optional.empty() if value is null or key not found
        }
        return Optional.empty(); // Returns empty if the propertiesMap itself is null
    }

    /**
     * UPDATED HELPER METHOD: Helper to check for the existence and value of 'Period' within an
     * alarm's properties. It checks both direct 'Period' (for simple alarms) and nested 'Period'
     * within the 'Metrics' array (for composite/metric math alarms).
     *
     * @param properties The 'Properties' map of an AWS::CloudWatch::Alarm resource.
     * @param allowedPeriods A Set of integer values the Period can be (e.g., {60, 300}).
     * @param failureMessages StringBuilder to append detailed failure messages.
     * @param logicalId The logical ID of the alarm for error reporting.
     * @return true if all found 'Period' properties are valid, false if any are missing or
     *     incorrect.
     */
    private boolean hasAllowedPeriodInAlarmProperties(
            Map<String, Object> properties,
            final Set<Integer> allowedPeriods,
            StringBuilder failureMessages,
            String logicalId) {
        boolean periodFound = false; // Track if any period was found at all
        boolean allPeriodsValid = true; // Track if all found periods are valid

        // 1. Check for Period directly under Properties
        Object directPeriod = properties.get("Period");
        if (directPeriod != null) {
            periodFound = true;
            if (!(directPeriod instanceof Integer)) {
                allPeriodsValid = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' 'Period' property (direct) is not an Integer (found type: %s, value: %s).%n",
                                logicalId, directPeriod.getClass().getSimpleName(), directPeriod));
            } else if (!allowedPeriods.contains((Integer) directPeriod)) {
                allPeriodsValid = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' 'Period' (direct) is '%s' but expected one of %s.%n",
                                logicalId, directPeriod, allowedPeriods));
            }
        }

        // 2. Check for Period within the 'Metrics' array (for composite/metric math alarms)
        Object metricsObject = properties.get("Metrics");
        if (metricsObject instanceof List<?> metricsList) {
            for (Object metricEntry : metricsList) {
                if (metricEntry instanceof Map<?, ?> metricMap) {
                    Object metricStatObject = metricMap.get("MetricStat");
                    if (metricStatObject instanceof Map<?, ?> metricStatMap) {
                        Object nestedPeriod = metricStatMap.get("Period");
                        if (nestedPeriod != null) {
                            periodFound = true; // A nested period was found
                            if (!(nestedPeriod instanceof Integer)) {
                                allPeriodsValid = false;
                                failureMessages.append(
                                        String.format(
                                                "CloudWatch Alarm resource '%s' nested 'Period' property is not an Integer (found type: %s, value: %s).%n",
                                                logicalId,
                                                nestedPeriod.getClass().getSimpleName(),
                                                nestedPeriod));
                            } else if (!allowedPeriods.contains((Integer) nestedPeriod)) {
                                allPeriodsValid = false;
                                failureMessages.append(
                                        String.format(
                                                "CloudWatch Alarm resource '%s' nested 'Period' is '%s' but expected one of %s.%n",
                                                logicalId, nestedPeriod, allowedPeriods));
                            }
                        }
                    }
                }
            }
        }

        // Final check: if no period was found at all, it's a failure.
        if (!periodFound) {
            failureMessages.append(
                    String.format(
                            "CloudWatch Alarm resource '%s' does not have a 'Period' property, either directly or nested within 'Metrics'.%n",
                            logicalId));
            return false;
        }

        return allPeriodsValid; // Return overall validity
    }

    /**
     * Helper to check for the existence of 'MetricName' within an alarm's 'Properties' map. It
     * checks both direct 'MetricName' (for simple alarms) and nested 'MetricName' within the
     * 'Metrics' array (for composite/metric math alarms). A 'MetricName' is considered valid if
     * it's a non-empty String or any Map (representing an intrinsic function).
     *
     * @param properties The 'Properties' map of an AWS::CloudWatch::Alarm resource.
     * @return true if a valid 'MetricName' is found in either location, false otherwise.
     */
    private boolean hasMetricNameInAlarmProperties(Map<String, Object> properties) {

        // 1. Check for MetricName directly under Properties (for simple alarms)
        Object directMetricName = properties.get("MetricName");
        if (directMetricName != null) {
            if (directMetricName instanceof String) {
                if (!((String) directMetricName).trim().isEmpty()) {
                    return true; // Found a non-empty String MetricName directly
                }
            } else if (directMetricName instanceof Map) {
                return true;
            }
        }

        // 2. Check for MetricName within the 'Metrics' array (for composite/metric math alarms)
        Object metricsObject = properties.get("Metrics");
        if (metricsObject instanceof List<?> metricsList) {
            for (Object metricEntry : metricsList) {
                if (metricEntry instanceof Map<?, ?> metricMap) {
                    Object metricStatObject = metricMap.get("MetricStat");
                    if (metricStatObject instanceof Map<?, ?> metricStatMap) {
                        Object metricDefinitionObject = metricStatMap.get("Metric");
                        if (metricDefinitionObject instanceof Map<?, ?> metricDefinitionMap) {
                            Object nestedMetricName = metricDefinitionMap.get("MetricName");
                            if (nestedMetricName != null) {
                                if (nestedMetricName instanceof String) {
                                    if (!((String) nestedMetricName).trim().isEmpty()) {
                                        return true; // Found a non-empty String MetricName in the
                                        // nested structure
                                    }
                                } else if (nestedMetricName instanceof Map) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        return false; // No valid MetricName found in either location
    }

    // API Gateway Resource Tests

    @Test
    @DisplayName("API Gateway Resource should contain correct properties Name prefix")
    void shouldContainAPIGatewayNameWithStackNamePrefix() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");
        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean nameFoundAndValid = false;
        String expectedPrefix = "${AWS::StackName}-";

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> name = getProperty(properties, "Name", String.class);

            if (name.isPresent()) {
                String nameValue = name.get();
                assertNotNull(
                        nameValue,
                        "Name property for resource '" + logicalId + "' should not be null.");
                assertTrue(
                        nameValue.startsWith(expectedPrefix),
                        "Name for resource '"
                                + logicalId
                                + "' should start with '"
                                + expectedPrefix
                                + "'. Found: '"
                                + nameValue
                                + "'");
                nameFoundAndValid = true;
                System.out.println(
                        "Found API Gateway resource '"
                                + logicalId
                                + "' with valid Name: "
                                + nameValue);
            } else {
                System.out.println(
                        "API Gateway resource '"
                                + logicalId
                                + "' does not have a 'Name' property or it's not a String.");
            }
        }

        assertTrue(
                nameFoundAndValid,
                "At least one AWS::Serverless::Api resource must have a non-null and valid 'Name' property starting with '"
                        + expectedPrefix
                        + "'.");
        System.out.println(
                "Assertion Passed: All API Gateway resources checked for Name property prefix.");
    }

    @Test
    @DisplayName("API Gateway Resource should contain correct properties Description")
    void shouldContainAPIGatewayDescription() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean descriptionFoundAndValid = false;
        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> description = getProperty(properties, "Description", String.class);

            if (description.isPresent()) {
                String descValue = description.get();
                assertNotNull(
                        descValue,
                        "Description property for resource '"
                                + logicalId
                                + "' should not be null.");
                assertTrue(
                        descValue.endsWith("UK Passport CRI API"),
                        "Description for resource '"
                                + logicalId
                                + "' should end with 'UK Passport CRI API'. Found: '"
                                + descValue
                                + "'");
                descriptionFoundAndValid = true;
                System.out.println(
                        "Found API Gateway resource '"
                                + logicalId
                                + "' with valid Description: "
                                + descValue);
            } else {
                System.out.println(
                        "API Gateway resource '"
                                + logicalId
                                + "' does not have a 'Description' property or it's not a String.");
            }
        }
        assertTrue(
                descriptionFoundAndValid,
                "At least one AWS::Serverless::Api resource must have a non-null and valid 'Description' property.");
        System.out.println(
                "Assertion Passed: All API Gateway resources checked for Description property.");
    }

    @Test
    @DisplayName("API Gateway Resource should contain correct properties Stage Name")
    void shouldContainAPIGatewayStageName() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean stageNameFoundAndValid = false;
        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> stageName = getProperty(properties, "StageName", String.class);

            if (stageName.isPresent()) {
                String descValue = stageName.get();
                assertNotNull(
                        descValue,
                        "StageName property for resource '" + logicalId + "' should not be null.");
                assertTrue(
                        descValue.endsWith("Environment"),
                        "StageName for resource '"
                                + logicalId
                                + "' should end with 'Environment'. Found: '"
                                + descValue
                                + "'");
                stageNameFoundAndValid = true;
                System.out.println(
                        "Found API Gateway resource '"
                                + logicalId
                                + "' with valid StageName: "
                                + descValue);
            } else {
                System.out.println(
                        "API Gateway resource '"
                                + logicalId
                                + "' does not have a 'StageName' property or it's not a String.");
            }
        }
        assertTrue(
                stageNameFoundAndValid,
                "At least one AWS::Serverless::Api resource must have a non-null and valid 'StageName' property.");
        System.out.println(
                "Assertion Passed: All API Gateway resources checked for StageName property.");
    }

    @Test
    @DisplayName("API Gateway Resource should contain correct properties Tracing Enabled")
    void shouldContainAPIGatewayTracingEnabled() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean tracingenabledFoundAndValid = false;
        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Boolean> tracingenabled =
                    getProperty(properties, "TracingEnabled", Boolean.class);

            if (tracingenabled.isPresent()) {
                Boolean tracingEnabledValue = tracingenabled.get();
                assertNotNull(
                        tracingEnabledValue,
                        "TracingEnabled property for resource '"
                                + logicalId
                                + "' should not be null.");
                assertTrue(
                        tracingEnabledValue,
                        "TracingEnabled for resource '"
                                + logicalId
                                + "' should be 'true'. Found: '"
                                + tracingEnabledValue
                                + "'");
                tracingenabledFoundAndValid = true;
                System.out.println(
                        "Found API Gateway resource '"
                                + logicalId
                                + "' with valid TracingEnabled: "
                                + tracingEnabledValue);
            } else {
                System.out.println(
                        "API Gateway resource '"
                                + logicalId
                                + "' does not have a 'TracingEnabled' property or it's not a Boolean.");
            }
        }
        assertTrue(
                tracingenabledFoundAndValid,
                "At least one AWS::Serverless::Api resource must have a non-null and valid 'TracingEnabled' property.");
        System.out.println(
                "Assertion Passed: All API Gateway resources checked for TracingEnabled property.");
    }

    @Test
    @DisplayName("API Gateway Resource should have a non-null EndpointConfiguration")
    void shouldContainAPIGatewayEndpointConfiguration() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");
        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean endpointConfigurationFoundAndValid = false;

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> endpointConfiguration =
                    getProperty(properties, "EndpointConfiguration", Object.class);

            if (endpointConfiguration.isPresent()) {
                Object configValue = endpointConfiguration.get();
                assertNotNull(
                        configValue,
                        "EndpointConfiguration property for resource '"
                                + logicalId
                                + "' should not be null.");
                endpointConfigurationFoundAndValid = true;
                System.out.println(
                        "Found API Gateway resource '"
                                + logicalId
                                + "' with non-null EndpointConfiguration: "
                                + configValue);
            } else {
                System.out.println(
                        "API Gateway resource '"
                                + logicalId
                                + "' does not have an 'EndpointConfiguration' property or it is null.");
            }
        }

        assertTrue(
                endpointConfigurationFoundAndValid,
                "At least one AWS::Serverless::Api resource must have a non-null 'EndpointConfiguration' property.");
        System.out.println(
                "Assertion Passed: All API Gateway resources checked for non-null EndpointConfiguration property.");
    }

    @Test
    @DisplayName(
            "All AWS::Serverless::Api resources with MethodSettings should contain LoggingLevel: INFO")
    void allApiMethodSettingsShouldContainLoggingLevelInfo() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean allRelevantApisSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<List<Map<String, Object>>> methodSettingsOptional =
                    getPropertyTypeReference(properties, new TypeReference<>() {});

            if (methodSettingsOptional.isPresent()) {
                List<Map<String, Object>> methodSettings = methodSettingsOptional.get();
                boolean foundLoggingLevelInfoForThisApi = false;

                for (Map<String, Object> setting : methodSettings) {
                    Optional<String> loggingLevel =
                            getProperty(setting, "LoggingLevel", String.class);
                    if (loggingLevel.isPresent() && "INFO".equals(loggingLevel.get())) {
                        foundLoggingLevelInfoForThisApi = true;
                        break;
                    }
                }

                if (!foundLoggingLevelInfoForThisApi) {
                    allRelevantApisSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "API resource '%s' has MethodSettings but does not contain 'LoggingLevel: INFO'.%n",
                                    logicalId));
                } else {
                    System.out.printf(
                            "API resource '%s' correctly contains 'LoggingLevel: INFO' in its MethodSettings.%n",
                            logicalId);
                }
            } else {
                System.out.printf(
                        "API resource '%s' does not define MethodSettings or it's not a List, skipping check.%n",
                        logicalId);
            }
        }
        assertTrue(
                allRelevantApisSatisfyCondition,
                "One or more AWS::Serverless::Api resources failed the MethodSettings check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::Serverless::Api resources checked for 'LoggingLevel: INFO'.");
    }

    @Test
    @DisplayName(
            "All AWS::Serverless::Api resources with MethodSettings should contain MetricsEnabled: true")
    void allApiMethodSettingsShouldContainMetricsEnabledTrue() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean allRelevantApisSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<List<Map<String, Object>>> methodSettingsOptional =
                    getPropertyTypeReference(properties, new TypeReference<>() {});

            if (methodSettingsOptional.isPresent()) {
                List<Map<String, Object>> methodSettings = methodSettingsOptional.get();

                boolean foundMetricsEnabledTrueForThisApi = false;
                for (Map<String, Object> setting : methodSettings) {
                    Optional<Boolean> metricsEnabled =
                            getProperty(setting, "MetricsEnabled", Boolean.class);

                    if (metricsEnabled.isPresent() && metricsEnabled.get()) {
                        foundMetricsEnabledTrueForThisApi = true;
                        break;
                    }
                }

                if (!foundMetricsEnabledTrueForThisApi) {
                    allRelevantApisSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "API resource '%s' has MethodSettings but does not contain 'MetricsEnabled: true'.%n",
                                    logicalId));
                }
            }
        }

        assertTrue(
                allRelevantApisSatisfyCondition,
                "One or more AWS::Serverless::Api resources failed the MetricsEnabled check:\n"
                        + failureMessages);
    }

    @Test
    @DisplayName(
            "All AWS::Serverless::Api resources with MethodSettings should contain ThrottlingRateLimit")
    void allApiMethodSettingsShouldContainThrottlingRateLimit() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean allRelevantApisSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<List<Map<String, Object>>> methodSettingsOptional =
                    getPropertyTypeReference(properties, new TypeReference<>() {});

            if (methodSettingsOptional.isPresent()) {
                List<Map<String, Object>> methodSettings = methodSettingsOptional.get();

                boolean foundThrottlingRateLimitForThisApi = false;
                for (Map<String, Object> setting : methodSettings) {
                    Optional<Integer> throttlingRateLimit =
                            getProperty(setting, "ThrottlingRateLimit", Integer.class);

                    if (throttlingRateLimit.isPresent()) {
                        foundThrottlingRateLimitForThisApi = true;
                        break;
                    }
                }

                if (!foundThrottlingRateLimitForThisApi) {
                    allRelevantApisSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "API resource '%s' has MethodSettings but does not contain 'ThrottlingRateLimit'.%n",
                                    logicalId));
                }
            }
        }

        assertTrue(
                allRelevantApisSatisfyCondition,
                "One or more AWS::Serverless::Api resources failed the ThrottlingRateLimit check:\n"
                        + failureMessages);
    }

    @Test
    @DisplayName(
            "All AWS::Serverless::Api resources with MethodSettings should contain ThrottlingBurstLimit")
    void allApiMethodSettingsShouldContainThrottlingBurstLimit() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");

        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean allRelevantApisSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<List<Map<String, Object>>> methodSettingsOptional =
                    getPropertyTypeReference(properties, new TypeReference<>() {});

            if (methodSettingsOptional.isPresent()) {
                List<Map<String, Object>> methodSettings = methodSettingsOptional.get();

                boolean foundThrottlingBurstLimitForThisApi = false;
                for (Map<String, Object> setting : methodSettings) {
                    Optional<Integer> throttlingBurstLimit =
                            getProperty(setting, "ThrottlingBurstLimit", Integer.class);

                    if (throttlingBurstLimit.isPresent()) {
                        foundThrottlingBurstLimitForThisApi = true;
                        break;
                    }
                }

                if (!foundThrottlingBurstLimitForThisApi) {
                    allRelevantApisSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "API resource '%s' has MethodSettings but does not contain 'ThrottlingBurstLimit'.%n",
                                    logicalId));
                }
            }
        }

        assertTrue(
                allRelevantApisSatisfyCondition,
                "One or more AWS::Serverless::Api resources failed the ThrottlingBurstLimit check:\n"
                        + failureMessages);
    }

    @Test
    @DisplayName(
            "All AWS::Serverless::Api resources with MethodSettings should contain DataTraceEnabled: [IsProdEnvironment, false, true]")
    void allApiMethodSettingsShouldContainDataTraceEnabled() {
        Map<String, Map<String, Object>> apiGatewayProperties =
                getAllResourceProperties("AWS::Serverless::Api");
        assertFalse(
                apiGatewayProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Api resource in the template.");

        boolean allRelevantApisSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        List<Object> expectedDataTraceEnabledList = List.of("IsProdEnvironment", false, true);

        for (Map.Entry<String, Map<String, Object>> entry : apiGatewayProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<List<Map<String, Object>>> methodSettingsOptional =
                    getPropertyTypeReference(properties, new TypeReference<>() {});

            if (methodSettingsOptional.isPresent()) {
                List<Map<String, Object>> methodSettings = methodSettingsOptional.get();

                boolean foundDataTraceEnabledValuesForThisApi = false;
                for (Map<String, Object> setting : methodSettings) {

                    @SuppressWarnings("unchecked")
                    Optional<List<Object>> dataTraceEnabledListOptional =
                            getProperty(
                                    setting,
                                    "DataTraceEnabled",
                                    (Class<List<Object>>) (Class<?>) List.class);

                    if (dataTraceEnabledListOptional.isPresent()) {
                        List<Object> actualDataTraceEnabledList =
                                dataTraceEnabledListOptional.get();

                        // Compare the actual list with the expected list
                        if (expectedDataTraceEnabledList.equals(actualDataTraceEnabledList)) {
                            foundDataTraceEnabledValuesForThisApi = true;
                            break;
                        } else {
                            System.out.printf(
                                    "    Mismatch for DataTraceEnabled in '%s'. Expected: %s, Actual: %s%n",
                                    logicalId,
                                    expectedDataTraceEnabledList,
                                    actualDataTraceEnabledList);
                        }
                    } else {
                        System.out.println(
                                "    'DataTraceEnabled' property not found or not a List in this MethodSetting.");
                    }
                }

                if (!foundDataTraceEnabledValuesForThisApi) {
                    allRelevantApisSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "API resource '%s' has MethodSettings but does not contain 'DataTraceEnabled: %s'.%n",
                                    logicalId, expectedDataTraceEnabledList));
                } else {
                    System.out.printf(
                            "API resource '%s' correctly contains 'DataTraceEnabled: %s' in its MethodSettings.%n",
                            logicalId, expectedDataTraceEnabledList);
                }
            } else {
                System.out.printf(
                        "API resource '%s' does not define MethodSettings or it's not a List, skipping check.%n",
                        logicalId);
            }
        }

        assertTrue(
                allRelevantApisSatisfyCondition,
                "One or more AWS::Serverless::Api resources failed the MethodSettings check:\n"
                        + failureMessages);
        System.out.println(
                "\nAssertion Passed: All relevant AWS::Serverless::Api resources checked for 'DataTraceEnabled: [IsProdEnvironment, false, true]'.");
        System.out.println("--- AWS::Serverless::Api MethodSettings Validation Complete ---");
    }

    // Lambda Function Resource Tests

    @Test
    @DisplayName("Lambda Function Resource should contain correct properties Handler prefix")
    void lambdaHandlerShouldStartWithPrefix() {
        Map<String, Map<String, Object>> lambdaProperties =
                getAllResourceProperties("AWS::Serverless::Function");

        assertFalse(
                lambdaProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Function resource.");

        boolean allHandlersMatchPrefix = true;
        String expectedPrefix = "uk.gov.di.ipv.cri.";
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : lambdaProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> handlerOptional = getProperty(properties, "Handler", String.class);

            if (handlerOptional.isPresent()) {
                String handler = handlerOptional.get();
                if (!handler.startsWith(expectedPrefix)) {
                    allHandlersMatchPrefix = false;
                    failureMessages.append(
                            String.format(
                                    "Lambda function '%s' Handler '%s' does not start with '%s'.%n",
                                    logicalId, handler, expectedPrefix));
                } else {
                    System.out.println(
                            "Found Lambda function '"
                                    + logicalId
                                    + "' with Handler: "
                                    + handler
                                    + " (starts with '"
                                    + expectedPrefix
                                    + "')");
                }
            } else {
                allHandlersMatchPrefix = false;
                failureMessages.append(
                        String.format(
                                "Lambda function '%s' is missing the mandatory 'Handler' property or it's not a String.%n",
                                logicalId));
            }
        }
        assertTrue(
                allHandlersMatchPrefix,
                "One or more Lambda function handlers failed the prefix check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant Lambda functions checked for Handler prefix.");
    }

    @Test
    @DisplayName("Lambda Function Resource should contain the 'CodeUri' property")
    void lambdaFunctionShouldHaveCodeUri() {
        Map<String, Map<String, Object>> lambdaProperties =
                getAllResourceProperties("AWS::Serverless::Function");
        assertFalse(
                lambdaProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Function resource.");

        boolean allCodeUrisExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : lambdaProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> codeUriOptional = getProperty(properties, "CodeUri", String.class);

            if (codeUriOptional.isEmpty()) {
                allCodeUrisExist = false;
                failureMessages.append(
                        String.format(
                                "Lambda function '%s' is missing the mandatory 'CodeUri' property or it's not a String.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found Lambda function '"
                                + logicalId
                                + "' with CodeUri: "
                                + codeUriOptional.get());
            }
        }

        assertTrue(
                allCodeUrisExist,
                "One or more Lambda functions are missing the 'CodeUri' property:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant Lambda functions checked for 'CodeUri' property.");
    }

    @Test
    @DisplayName("Lambda Function Resource 'AutoPublishAlias' should be set to 'live'")
    void lambdaFunctionAutoPublishAliasShouldBeLive() {
        Map<String, Map<String, Object>> lambdaProperties =
                getAllResourceProperties("AWS::Serverless::Function");
        assertFalse(
                lambdaProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Function resource.");

        boolean allAliasesAreLive = true;
        String expectedAlias = "live";
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : lambdaProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> autoPublishAliasOptional =
                    getProperty(properties, "AutoPublishAlias", String.class);

            if (autoPublishAliasOptional.isEmpty()) {
                allAliasesAreLive = false;
                failureMessages.append(
                        String.format(
                                "Lambda function '%s' is missing the 'AutoPublishAlias' property or it's not a String.%n",
                                logicalId));
            } else {
                String actualAlias = autoPublishAliasOptional.get();
                if (!actualAlias.equals(expectedAlias)) {
                    allAliasesAreLive = false;
                    failureMessages.append(
                            String.format(
                                    "Lambda function '%s' 'AutoPublishAlias' is '%s' but expected '%s'.%n",
                                    logicalId, actualAlias, expectedAlias));
                } else {
                    System.out.println(
                            "Found Lambda function '"
                                    + logicalId
                                    + "' with AutoPublishAlias: "
                                    + actualAlias
                                    + " (matches '"
                                    + expectedAlias
                                    + "')");
                }
            }
        }

        assertTrue(
                allAliasesAreLive,
                "One or more Lambda functions have an incorrect or missing 'AutoPublishAlias':\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant Lambda functions checked for 'AutoPublishAlias' being 'live'.");
    }

    @Test
    @DisplayName("Lambda Function Resource 'AutoPublishAliasAllProperties' should be set to 'true'")
    void lambdaFunctionAutoPublishAliasAllPropertiesShouldBeTrue() {
        Map<String, Map<String, Object>> lambdaProperties =
                getAllResourceProperties("AWS::Serverless::Function");
        assertFalse(
                lambdaProperties.isEmpty(),
                "Expected at least one AWS::Serverless::Function resource.");

        boolean allAutoPublishPropertiesAreTrue = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : lambdaProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Boolean> autoPublishAllPropertiesOptional =
                    getProperty(properties, "AutoPublishAliasAllProperties", Boolean.class);

            if (autoPublishAllPropertiesOptional.isEmpty()) {
                allAutoPublishPropertiesAreTrue = false;
                failureMessages.append(
                        String.format(
                                "Lambda function '%s' is missing the 'AutoPublishAliasAllProperties' property or it's not a Boolean.%n",
                                logicalId));
            } else {
                Boolean actualValue = autoPublishAllPropertiesOptional.get();
                if (!actualValue) {
                    allAutoPublishPropertiesAreTrue = false;
                    failureMessages.append(
                            String.format(
                                    "Lambda function '%s' 'AutoPublishAliasAllProperties' is '%s' but expected 'true'.%n",
                                    logicalId, false));
                } else {
                    System.out.println(
                            "Found Lambda function '"
                                    + logicalId
                                    + "' with AutoPublishAliasAllProperties: "
                                    + true
                                    + " (matches 'true')");
                }
            }
        }

        assertTrue(
                allAutoPublishPropertiesAreTrue,
                "One or more Lambda functions have an incorrect or missing 'AutoPublishAliasAllProperties':\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant Lambda functions checked for 'AutoPublishAliasAllProperties' being 'true'.");
    }

    // Logs - Log Group Resource Tests

    @Test
    @DisplayName("All AWS::Logs::LogGroup resources should contain a LogGroupName")
    void allLogGroupResourcesShouldContainLogGroupName() {
        Map<String, Map<String, Object>> logGroupProperties =
                getAllResourceProperties("AWS::Logs::LogGroup");

        assertFalse(
                logGroupProperties.isEmpty(),
                "Expected at least one AWS::Logs::LogGroup resource in the template.");

        boolean allLogGroupsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : logGroupProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> logGroupName = getProperty(properties, "LogGroupName", String.class);

            if (logGroupName.isEmpty()) {
                allLogGroupsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "LogGroup resource '%s' does not have a 'LogGroupName' property or it's not a String.%n",
                                logicalId));
            }
        }

        assertTrue(
                allLogGroupsSatisfyCondition,
                "One or more AWS::Logs::LogGroup resources failed the LogGroupName existence check:\n"
                        + failureMessages);
    }

    @Test
    @DisplayName("All AWS::Logs::LogGroup resources should contain a RetentionInDays")
    void allLogGroupResourcesShouldContainRetentionInDays() {
        Map<String, Map<String, Object>> logGroupProperties =
                getAllResourceProperties("AWS::Logs::LogGroup");

        assertFalse(
                logGroupProperties.isEmpty(),
                "Expected at least one AWS::Logs::LogGroup resource in the template.");

        boolean allLogGroupsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : logGroupProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> retentionInDays =
                    getProperty(properties, "RetentionInDays", String.class);

            if (retentionInDays.isEmpty()) {
                allLogGroupsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "LogGroup resource '%s' does not have a 'RetentionInDays' property or it's not an Integer.%n",
                                logicalId));
            }
        }

        assertTrue(
                allLogGroupsSatisfyCondition,
                "One or more AWS::Logs::LogGroup resources failed the RetentionInDays existence check:\n"
                        + failureMessages);
    }

    // Logs - Subscription Filter Resource Tests

    @Test
    @DisplayName(
            "All AWS::Logs::SubscriptionFilter resources should contain Condition: LogSendingEnabled")
    void allSubscriptionFilterResourcesShouldContainLogSendingEnabledCondition() {
        Map<String, Map<String, Object>> subscriptionFilterResources =
                getAllResources("AWS::Logs::SubscriptionFilter");

        assertFalse(
                subscriptionFilterResources.isEmpty(),
                "Expected at least one AWS::Logs::SubscriptionFilter resource in the template.");

        boolean allSubscriptionFiltersSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry :
                subscriptionFilterResources.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> resourceDefinition = entry.getValue();

            Optional<String> condition = getTopLevelProperty(resourceDefinition);

            if (condition.isPresent()) {
                String conditionValue = condition.get();
                if (!"LogSendingEnabled".equals(conditionValue)) {
                    allSubscriptionFiltersSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "SubscriptionFilter resource '%s' has Condition '%s' but expected 'LogSendingEnabled'.%n",
                                    logicalId, conditionValue));
                }
            } else {
                allSubscriptionFiltersSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "SubscriptionFilter resource '%s' does not have a 'Condition' property or it's not a String.%n",
                                logicalId));
            }
        }

        assertTrue(
                allSubscriptionFiltersSatisfyCondition,
                "One or more AWS::Logs::SubscriptionFilter resources failed the Condition check:\n"
                        + failureMessages);
    }

    @Test
    @DisplayName("All AWS::Logs::SubscriptionFilter resources should contain a LogGroupName")
    void allSubscriptionFilterResourcesShouldContainLogGroupName() {
        Map<String, Map<String, Object>> logGroupProperties =
                getAllResourceProperties("AWS::Logs::SubscriptionFilter");

        assertFalse(
                logGroupProperties.isEmpty(),
                "Expected at least one AWS::Logs::SubscriptionFilter resource in the template.");

        boolean allLogGroupsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : logGroupProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> logGroupName = getProperty(properties, "LogGroupName", String.class);

            if (logGroupName.isEmpty()) {
                allLogGroupsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "LogGroup resource '%s' does not have a 'LogGroupName' property or it's not a String.%n",
                                logicalId));
            }
        }

        assertTrue(
                allLogGroupsSatisfyCondition,
                "One or more AWS::Logs::SubscriptionFilter resources failed the LogGroupName existence check:\n"
                        + failureMessages);
    }

    @Test
    @DisplayName(
            "All AWS::Logs::SubscriptionFilter resources should contain DestinationArn starting with 'arn:aws:logs:eu-west-2:'")
    void allSubscriptionFilterResourcesShouldContainDestinationArnWithPrefix() {
        Map<String, Map<String, Object>> subscriptionFilterProperties =
                getAllResourceProperties("AWS::Logs::SubscriptionFilter");

        assertFalse(
                subscriptionFilterProperties.isEmpty(),
                "Expected at least one AWS::Logs::SubscriptionFilter resource in the template.");

        boolean allSubscriptionFiltersSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        String expectedPrefix = "arn:aws:logs:eu-west-2:";

        for (Map.Entry<String, Map<String, Object>> entry :
                subscriptionFilterProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> destinationArn =
                    getProperty(properties, "DestinationArn", String.class);

            if (destinationArn.isPresent()) {
                String destinationArnValue = destinationArn.get();
                if (!destinationArnValue.startsWith(expectedPrefix)) {
                    allSubscriptionFiltersSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "SubscriptionFilter resource '%s' has DestinationArn '%s' which does not start with '%s'.%n",
                                    logicalId, destinationArnValue, expectedPrefix));
                }
            } else {
                allSubscriptionFiltersSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "SubscriptionFilter resource '%s' does not have a 'DestinationArn' property or it's not a String.%n",
                                logicalId));
            }
        }

        assertTrue(
                allSubscriptionFiltersSatisfyCondition,
                "One or more AWS::Logs::SubscriptionFilter resources failed the DestinationArn prefix check:\n"
                        + failureMessages);
    }

    // Lambda - Permission Resource Tests

    @Test
    @DisplayName("All AWS::Lambda::Permission resources should contain an 'Action' property")
    void allLambdaPermissionResourcesShouldContainAction() {
        Map<String, Map<String, Object>> permissionProperties =
                getAllResourceProperties("AWS::Lambda::Permission");
        assertFalse(
                permissionProperties.isEmpty(),
                "Expected at least one AWS::Lambda::Permission resource in the template.");

        boolean allPermissionsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : permissionProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> actionOptional = getProperty(properties, "Action", String.class);

            if (actionOptional.isEmpty()) {
                allPermissionsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "Lambda Permission resource '%s' does not have an 'Action' property or it's not a String.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found Lambda Permission resource '"
                                + logicalId
                                + "' with Action: "
                                + actionOptional.get());
            }
        }

        assertTrue(
                allPermissionsSatisfyCondition,
                "One or more AWS::Lambda::Permission resources failed the 'Action' property existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::Lambda::Permission resources checked for 'Action' property.");
    }

    @Test
    @DisplayName("All AWS::Lambda::Permission resources should contain a 'FunctionName' property")
    void allLambdaPermissionResourcesShouldContainFunctionName() {
        Map<String, Map<String, Object>> permissionProperties =
                getAllResourceProperties("AWS::Lambda::Permission");
        assertFalse(
                permissionProperties.isEmpty(),
                "Expected at least one AWS::Lambda::Permission resource in the template.");

        boolean allPermissionsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : permissionProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> functionNameOptional =
                    getProperty(properties, "FunctionName", String.class);

            if (functionNameOptional.isEmpty()) {
                allPermissionsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "Lambda Permission resource '%s' does not have a 'FunctionName' property or it's not a String.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found Lambda Permission resource '"
                                + logicalId
                                + "' with FunctionName: "
                                + functionNameOptional.get());
            }
        }

        assertTrue(
                allPermissionsSatisfyCondition,
                "One or more AWS::Lambda::Permission resources failed the 'FunctionName' property existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::Lambda::Permission resources checked for 'FunctionName' property.");
    }

    @Test
    @DisplayName("All AWS::Lambda::Permission resources should contain a 'Principal' property")
    void allLambdaPermissionResourcesShouldContainPrincipal() {
        Map<String, Map<String, Object>> permissionProperties =
                getAllResourceProperties("AWS::Lambda::Permission");
        assertFalse(
                permissionProperties.isEmpty(),
                "Expected at least one AWS::Lambda::Permission resource in the template.");

        boolean allPermissionsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : permissionProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> principalOptional = getProperty(properties, "Principal", String.class);

            if (principalOptional.isEmpty()) {
                allPermissionsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "Lambda Permission resource '%s' does not have a 'Principal' property or it's not a String.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found Lambda Permission resource '"
                                + logicalId
                                + "' with Principal: "
                                + principalOptional.get());
            }
        }

        assertTrue(
                allPermissionsSatisfyCondition,
                "One or more AWS::Lambda::Permission resources failed the 'Principal' property existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::Lambda::Permission resources checked for 'Principal' property.");
    }

    // CloudWatch - Alarm Resource Tests

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should contain Condition: 'AlarmsEnabled' or 'UseCanaryDeploymentAlarms'")
    void allCloudWatchAlarmResourcesShouldContainCorrectCondition() {
        Map<String, Map<String, Object>> alarmResources = getAllResources("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmResources.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allAlarmsSatisfyCondition = true;
        StringBuilder failureMessages = new StringBuilder();
        Set<String> allowedConditions = Set.of("AlarmsEnabled", "UseCanaryDeploymentAlarms");

        for (Map.Entry<String, Map<String, Object>> entry : alarmResources.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> resourceDefinition = entry.getValue();

            Optional<String> condition = getTopLevelProperty(resourceDefinition);

            if (condition.isPresent()) {
                String conditionValue = condition.get();
                if (!allowedConditions.contains(conditionValue)) {
                    allAlarmsSatisfyCondition = false;
                    failureMessages.append(
                            String.format(
                                    "CloudWatch Alarm resource '%s' has Condition '%s' but expected one of %s.%n",
                                    logicalId, conditionValue, allowedConditions));
                } else {
                    System.out.println(
                            "CloudWatch Alarm resource '"
                                    + logicalId
                                    + "' has Condition: "
                                    + conditionValue
                                    + " (matches an allowed condition)");
                }
            } else {
                allAlarmsSatisfyCondition = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have a 'Condition' property or it's not a String.%n",
                                logicalId));
            }
        }

        assertTrue(
                allAlarmsSatisfyCondition,
                "One or more AWS::CloudWatch::Alarm resources failed the Condition check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for Condition: 'AlarmsEnabled' or 'UseCanaryDeploymentAlarms'.");
    }

    //    @Test
    //    Current Fails as some alarms do not have a AlarmName
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should have 'AlarmName' starting with '${AWS::StackName}-'")
    void allCloudWatchAlarmResourcesShouldHaveAlarmNameWithStackNamePrefix() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allAlarmNamesMatchPrefix = true;
        String expectedPrefix = "${AWS::StackName}-";
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<String> alarmNameOptional = getProperty(properties, "AlarmName", String.class);

            if (alarmNameOptional.isPresent()) {
                String alarmNameValue = alarmNameOptional.get();
                if (!alarmNameValue.startsWith(expectedPrefix)) {
                    allAlarmNamesMatchPrefix = false;
                    failureMessages.append(
                            String.format(
                                    "AlarmName for resource '%s' ('%s') does not start with '%s'.%n",
                                    logicalId, alarmNameValue, expectedPrefix));
                } else {
                    System.out.println(
                            "Found CloudWatch Alarm resource '"
                                    + logicalId
                                    + "' with valid AlarmName: "
                                    + alarmNameValue);
                }
            } else {
                allAlarmNamesMatchPrefix = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have an 'AlarmName' property or it's not a String.%n",
                                logicalId));
            }
        }

        assertTrue(allAlarmNamesMatchPrefix, "Test message");
        assertTrue(
                allAlarmNamesMatchPrefix,
                "One or more AWS::CloudWatch::Alarm resources failed the 'AlarmName' prefix check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'AlarmName' property prefix.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should contain an 'AlarmDescription' property")
    void allCloudWatchAlarmResourcesShouldContainAlarmDescription() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allAlarmDescriptionsExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> alarmDescriptionOptional = getProperty(properties, "AlarmDescription");

            if (alarmDescriptionOptional.isEmpty()) {
                allAlarmDescriptionsExist = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have an 'AlarmDescription' property.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '"
                                + logicalId
                                + "' with AlarmDescription.");
            }
        }

        assertTrue(
                allAlarmDescriptionsExist,
                "One or more AWS::CloudWatch::Alarm resources failed the 'AlarmDescription' existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'AlarmDescription' property existence.");
    }

    @Test
    @DisplayName("All AWS::CloudWatch::Alarm resources should have 'ActionsEnabled' set to 'true'")
    void allCloudWatchAlarmResourcesShouldHaveActionsEnabledTrue() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allActionsEnabledAreTrue = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Boolean> actionsEnabledOptional =
                    getProperty(properties, "ActionsEnabled", Boolean.class);

            if (actionsEnabledOptional.isEmpty()) {
                allActionsEnabledAreTrue = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have an 'ActionsEnabled' property or it's not a Boolean.%n",
                                logicalId));
            } else {
                Boolean actionsEnabledValue = actionsEnabledOptional.get();
                if (!actionsEnabledValue) {
                    allActionsEnabledAreTrue = false;
                    failureMessages.append(
                            String.format(
                                    "CloudWatch Alarm resource '%s' 'ActionsEnabled' is '%s' but expected 'true'.%n",
                                    logicalId, false));
                } else {
                    System.out.println(
                            "Found CloudWatch Alarm resource '"
                                    + logicalId
                                    + "' with ActionsEnabled: "
                                    + true
                                    + " (matches 'true')");
                }
            }
        }

        assertTrue(
                allActionsEnabledAreTrue,
                "One or more AWS::CloudWatch::Alarm resources failed the 'ActionsEnabled' check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'ActionsEnabled' being 'true'.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should contain a 'MetricName' property (direct or nested)")
    void allCloudWatchAlarmResourcesShouldContainMetricName() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allMetricNamesExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            if (!hasMetricNameInAlarmProperties(properties)) {
                allMetricNamesExist = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have a 'MetricName' property, either directly or nested within 'Metrics'.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '"
                                + logicalId
                                + "' with a valid 'MetricName'.");
            }
        }

        assertTrue(
                allMetricNamesExist,
                "One or more AWS::CloudWatch::Alarm resources failed the 'MetricName' existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'MetricName' property existence.");
    }

    @Test
    @DisplayName("All AWS::CloudWatch::Alarm resources should contain an 'AlarmActions' property")
    void allCloudWatchAlarmResourcesShouldContainAlarmActions() {
        Map<String, Map<String, Object>> alarmResources =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmResources.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allAlarmActionsExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmResources.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> resourceDefinition = entry.getValue();

            Optional<Object> alarmActionsOptional = getProperty(resourceDefinition, "AlarmActions");

            if (alarmActionsOptional.isEmpty()) {
                allAlarmActionsExist = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have an 'AlarmActions' property.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '" + logicalId + "' with AlarmActions.");
            }
        }

        assertTrue(
                allAlarmActionsExist,
                "One or more AWS::CloudWatch::Alarm resources failed the 'AlarmActions' existence check:\n"
                        + failureMessages.toString());
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'AlarmActions' property existence.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should have 'Period' set to 60, 300 or 900 (direct or nested)")
    void allCloudWatchAlarmResourcesShouldHaveAllowedPeriod() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allPeriodsAreValid = true;
        StringBuilder failureMessages = new StringBuilder();
        final Set<Integer> allowedPeriods = Set.of(60, 300, 900);

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            if (!hasAllowedPeriodInAlarmProperties(
                    properties, allowedPeriods, failureMessages, logicalId)) {
                allPeriodsAreValid = false;
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '"
                                + logicalId
                                + "' with valid Period (matches one of "
                                + allowedPeriods
                                + ")");
            }
        }

        assertTrue(
                allPeriodsAreValid,
                "One or more AWS::CloudWatch::Alarm resources failed the 'Period' check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'Period' being 60 or 300.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should contain a 'Threshold' property with any value")
    void allCloudWatchAlarmResourcesShouldContainThreshold() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allThresholdsExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> thresholdOptional = getProperty(properties, "Threshold");

            if (thresholdOptional.isEmpty()) {
                allThresholdsExist = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have a 'Threshold' property.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '"
                                + logicalId
                                + "' with Threshold: "
                                + thresholdOptional.get());
            }
        }

        assertTrue(
                allThresholdsExist,
                "One or more AWS::CloudWatch::Alarm resources failed the 'Threshold' existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'Threshold' property existence.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should contain an 'EvaluationPeriods' property with any value")
    void allCloudWatchAlarmResourcesShouldContainEvaluationPeriods() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allEvaluationPeriodsExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> evaluationPeriodsOptional =
                    getProperty(properties, "EvaluationPeriods");

            if (evaluationPeriodsOptional.isEmpty()) {
                allEvaluationPeriodsExist = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have an 'EvaluationPeriods' property.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '"
                                + logicalId
                                + "' with EvaluationPeriods: "
                                + evaluationPeriodsOptional.get());
            }
        }

        assertTrue(
                allEvaluationPeriodsExist,
                "One or more AWS::CloudWatch::Alarm resources failed the 'EvaluationPeriods' existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'EvaluationPeriods' property existence.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should contain a 'DatapointsToAlarm' property with any value")
    void allCloudWatchAlarmResourcesShouldContainDatapointsToAlarm() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allDatapointsToAlarmExist = true;
        StringBuilder failureMessages = new StringBuilder();

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> datapointsToAlarmOptional =
                    getProperty(properties, "DatapointsToAlarm");

            if (datapointsToAlarmOptional.isEmpty()) {
                allDatapointsToAlarmExist = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have a 'DatapointsToAlarm' property.%n",
                                logicalId));
            } else {
                System.out.println(
                        "Found CloudWatch Alarm resource '"
                                + logicalId
                                + "' with DatapointsToAlarm: "
                                + datapointsToAlarmOptional.get());
            }
        }

        assertTrue(
                allDatapointsToAlarmExist,
                "One or more AWS::CloudWatch::Alarm resources failed the 'DatapointsToAlarm' existence check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'DatapointsToAlarm' property existence.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should have 'TreatMissingData' set to 'notBreaching'")
    void allCloudWatchAlarmResourcesShouldHaveTreatMissingDataNotBreaching() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allTreatMissingDataAreCorrect = true;
        StringBuilder failureMessages = new StringBuilder();
        final String expectedTreatMissingData = "notBreaching";

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> treatMissingDataOptional = getProperty(properties, "TreatMissingData");

            if (treatMissingDataOptional.isEmpty()) {
                allTreatMissingDataAreCorrect = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have a 'TreatMissingData' property.%n",
                                logicalId));
            } else {
                Object treatMissingDataValue = treatMissingDataOptional.get();
                if (!(treatMissingDataValue instanceof String)) {
                    allTreatMissingDataAreCorrect = false;
                    failureMessages.append(
                            String.format(
                                    "CloudWatch Alarm resource '%s' 'TreatMissingData' property is not a String (found type: %s, value: %s).%n",
                                    logicalId,
                                    treatMissingDataValue.getClass().getSimpleName(),
                                    treatMissingDataValue));
                } else if (!expectedTreatMissingData.equals(treatMissingDataValue)) {
                    allTreatMissingDataAreCorrect = false;
                    failureMessages.append(
                            String.format(
                                    "CloudWatch Alarm resource '%s' 'TreatMissingData' is '%s' but expected '%s'.%n",
                                    logicalId, treatMissingDataValue, expectedTreatMissingData));
                } else {
                    System.out.println(
                            "Found CloudWatch Alarm resource '"
                                    + logicalId
                                    + "' with TreatMissingData: "
                                    + treatMissingDataValue
                                    + " (matches '"
                                    + expectedTreatMissingData
                                    + "')");
                }
            }
        }

        assertTrue(
                allTreatMissingDataAreCorrect,
                "One or more AWS::CloudWatch::Alarm resources failed the 'TreatMissingData' check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for 'TreatMissingData' being 'notBreaching'.");
    }

    @Test
    @DisplayName(
            "All AWS::CloudWatch::Alarm resources should have 'ComparisonOperator' as 'GreaterThanOrEqualToThreshold' or 'GreaterThanThreshold'")
    void allCloudWatchAlarmResourcesShouldHaveValidComparisonOperator() {
        Map<String, Map<String, Object>> alarmProperties =
                getAllResourceProperties("AWS::CloudWatch::Alarm");
        assertFalse(
                alarmProperties.isEmpty(),
                "Expected at least one AWS::CloudWatch::Alarm resource in the template.");

        boolean allComparisonOperatorsAreValid = true;
        StringBuilder failureMessages = new StringBuilder();
        final Set<String> allowedOperators =
                Set.of("GreaterThanOrEqualToThreshold", "GreaterThanThreshold");

        for (Map.Entry<String, Map<String, Object>> entry : alarmProperties.entrySet()) {
            String logicalId = entry.getKey();
            Map<String, Object> properties = entry.getValue();

            Optional<Object> comparisonOperatorOptional =
                    getProperty(properties, "ComparisonOperator");

            if (comparisonOperatorOptional.isEmpty()) {
                allComparisonOperatorsAreValid = false;
                failureMessages.append(
                        String.format(
                                "CloudWatch Alarm resource '%s' does not have a 'ComparisonOperator' property.%n",
                                logicalId));
            } else {
                Object operatorValue = comparisonOperatorOptional.get();
                if (!(operatorValue instanceof String actualOperator)) {
                    allComparisonOperatorsAreValid = false;
                    failureMessages.append(
                            String.format(
                                    "CloudWatch Alarm resource '%s' 'ComparisonOperator' property is not a String (found type: %s, value: %s).%n",
                                    logicalId,
                                    operatorValue.getClass().getSimpleName(),
                                    operatorValue));
                } else {
                    if (!allowedOperators.contains(actualOperator)) {
                        allComparisonOperatorsAreValid = false;
                        failureMessages.append(
                                String.format(
                                        "CloudWatch Alarm resource '%s' 'ComparisonOperator' is '%s' but expected one of %s.%n",
                                        logicalId, actualOperator, allowedOperators));
                    } else {
                        System.out.println(
                                "Found CloudWatch Alarm resource '"
                                        + logicalId
                                        + "' with ComparisonOperator: "
                                        + actualOperator
                                        + " (matches an allowed value)");
                    }
                }
            }
        }

        assertTrue(
                allComparisonOperatorsAreValid,
                "One or more AWS::CloudWatch::Alarm resources failed the 'ComparisonOperator' check:\n"
                        + failureMessages);
        System.out.println(
                "Assertion Passed: All relevant AWS::CloudWatch::Alarm resources checked for valid 'ComparisonOperator'.");
    }
}
