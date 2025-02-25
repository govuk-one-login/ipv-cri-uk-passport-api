package uk.gov.di.ipv.cri.passport.testlambda.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.CorrelationIdPathConstants;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import software.amazon.lambda.powertools.parameters.SSMProvider;

public class TestLambdaHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final boolean READ_PARAM_IN_CONSTRUCTOR = false;

    private final SSMProvider ssmProvider;

    public TestLambdaHandler() {
        ClientProviderFactory clientProviderFactory = new ClientProviderFactory(true, false);

        ssmProvider = clientProviderFactory.getSSMProvider();

        if (READ_PARAM_IN_CONSTRUCTOR) {
            // When READ_PARAM_IN_CONSTRUCTOR=true, upon invoking the lambda the following message
            // appears in the logs
            // With all Dynatrace forwarding failing
            // [Dynatrace] 2025-02-25 16:17:56.392 UTC [00000001]
            // [com.dynatrace.shaded.io.opentelemetry.sdk.trace.TracerSharedState] WARNING Tried to
            // merge resource Resource{schemaUrl=null, attributes={cloud.account.id="....",
            // cloud.platform="aws_lambda", cloud.provider="aws", cloud.region="eu-west-2",
            // dt.tech.agent_detected_main_technology="aws_lambda",
            // faas.id=".....", faas.max_memory=4096, faas.name=".....", faas.version="10"}} too
            // late.
            String testParameter1Value =
                    this.getParameterValue(System.getenv("AWS_STACK_NAME"), "TestParameter1");

            LOGGER.info(
                    "Reading testParameter {} in Constructor - value is  {}",
                    "TestParameter1",
                    testParameter1Value);
        }
    }

    @Override
    @Logging(correlationIdPath = CorrelationIdPathConstants.API_GATEWAY_REST)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent, Context context) {

        try {
            LOGGER.info("Handling requests");

            String testParameter1Value =
                    this.getParameterValue(System.getenv("AWS_STACK_NAME"), "TestParameter1");
            LOGGER.info(
                    "Reading testParameter {} in Handler method - value is  {}",
                    "TestParameter1",
                    testParameter1Value);

            LOGGER.info("Returning response..");

            return new APIGatewayProxyResponseEvent().withBody("Success").withStatusCode(200);
        } catch (RuntimeException e) {

            LOGGER.error("Error handling requests", e);

            return new APIGatewayProxyResponseEvent().withBody("Failure").withStatusCode(500);
        }
    }

    public String getParameterValue(String prefix, String parameterName) {

        String parameterPath = String.format("/%s/%s", prefix, parameterName);

        LOGGER.info("{} {} {} - {}", "getParameterValue", prefix, parameterName, parameterPath);

        return ssmProvider.get(parameterPath);
    }
}
