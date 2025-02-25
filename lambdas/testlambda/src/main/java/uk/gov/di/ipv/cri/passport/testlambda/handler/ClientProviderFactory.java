package uk.gov.di.ipv.cri.passport.testlambda.handler;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.instrumentation.awssdk.v2_2.AwsSdkTelemetry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.awscore.defaultsmode.DefaultsMode;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.SsmClientBuilder;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;

public class ClientProviderFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SdkHttpClient sdkHttpClient;
    private final Region awsRegion;
    private final AwsCredentialsProvider awsCredentialsProvider;

    private static final DefaultsMode DEFAULTS_MODE = DefaultsMode.IN_REGION;

    private DynamoDbEnhancedClient dynamoDbEnhancedClient;
    private SsmClient ssmClient;
    private SSMProvider ssmProvider;
    private SecretsProvider secretsProvider;
    private SecretsManagerClient secretsManagerClient;

    private final boolean addOpenTelemetryExecutionInterceptors;
    // Override to work around a clash at Run-time with Dynatrace Agent
    private final boolean avoidExecutionInterceptorsOnClientsUsedByPowerTools;

    public ClientProviderFactory() {
        // The CRI is using opentelemetry-aws-sdk-2.2-autoconfigure
        this(false, false);
    }

    public ClientProviderFactory(
            boolean usingNonAutomaticOpenTelemetry,
            boolean avoidExecutionInterceptorsOnClientsUsedByPowerTools) {
        this.addOpenTelemetryExecutionInterceptors = usingNonAutomaticOpenTelemetry;
        this.avoidExecutionInterceptorsOnClientsUsedByPowerTools =
                avoidExecutionInterceptorsOnClientsUsedByPowerTools;

        awsRegion = Region.of(System.getenv("AWS_REGION"));

        // AWS SDK CRT Client (SYNC) - connection defaults are in SdkHttpConfigurationOption
        sdkHttpClient = AwsCrtHttpClient.builder().maxConcurrency(100).build();

        // Check if started inside a snap start container and use appropriate provider
        // see https://docs.aws.amazon.com/lambda/latest/dg/snapstart-activate.html
        awsCredentialsProvider =
                System.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") == null
                        ? EnvironmentVariableCredentialsProvider.create()
                        : ContainerCredentialsProvider.builder().build();
    }

    public AwsCredentialsProvider getAwsCredentialsProvider() {
        return awsCredentialsProvider;
    }

    public DynamoDbEnhancedClient getDynamoDbEnhancedClient() {
        if (null == dynamoDbEnhancedClient) {
            DynamoDbClientBuilder dynamoDbClientBuilder =
                    DynamoDbClient.builder()
                            .region(awsRegion)
                            .httpClient(sdkHttpClient)
                            .credentialsProvider(awsCredentialsProvider)
                            .defaultsMode(DEFAULTS_MODE);

            if (addOpenTelemetryExecutionInterceptors) {
                dynamoDbClientBuilder.overrideConfiguration(
                        ClientOverrideConfiguration.builder()
                                .addExecutionInterceptor(
                                        AwsSdkTelemetry.create(GlobalOpenTelemetry.get())
                                                .newExecutionInterceptor())
                                .build());
            }

            DynamoDbClient dynamoDbClient = dynamoDbClientBuilder.build();

            dynamoDbEnhancedClient =
                    DynamoDbEnhancedClient.builder().dynamoDbClient(dynamoDbClient).build();
        }

        return dynamoDbEnhancedClient;
    }

    public SsmClient getSsmClient() {

        if (null == ssmClient) {
            SsmClientBuilder ssmClientBuilder =
                    SsmClient.builder()
                            .region(awsRegion)
                            .httpClient(sdkHttpClient)
                            .credentialsProvider(awsCredentialsProvider)
                            .defaultsMode(DEFAULTS_MODE);

            if (addOpenTelemetryExecutionInterceptors
                    && !avoidExecutionInterceptorsOnClientsUsedByPowerTools) {
                ssmClientBuilder.overrideConfiguration(
                        ClientOverrideConfiguration.builder()
                                .addExecutionInterceptor(
                                        AwsSdkTelemetry.create(GlobalOpenTelemetry.get())
                                                .newExecutionInterceptor())
                                .build());
            }

            ssmClient = ssmClientBuilder.build();
        }

        return ssmClient;
    }

    public SSMProvider getSSMProvider() {

        if (null == ssmProvider) {
            ssmProvider = ParamManager.getSsmProvider(getSsmClient());
        }

        return ssmProvider;
    }

    public SecretsProvider getSecretsProvider() {

        if (null == secretsProvider) {

            secretsProvider = ParamManager.getSecretsProvider(getSecretsManagerClient());
        }
        return secretsProvider;
    }

    public SecretsManagerClient getSecretsManagerClient() {
        if (null == secretsManagerClient) {

            SecretsManagerClientBuilder secretsManagerClientBuilder =
                    SecretsManagerClient.builder()
                            .region(awsRegion)
                            .httpClient(sdkHttpClient)
                            .credentialsProvider(awsCredentialsProvider)
                            .defaultsMode(DEFAULTS_MODE);

            if (addOpenTelemetryExecutionInterceptors) {
                secretsManagerClientBuilder.overrideConfiguration(
                        ClientOverrideConfiguration.builder()
                                .addExecutionInterceptor(
                                        AwsSdkTelemetry.create(GlobalOpenTelemetry.get())
                                                .newExecutionInterceptor())
                                .build());
            }

            secretsManagerClient = secretsManagerClientBuilder.build();
        }

        return secretsManagerClient;
    }
}
