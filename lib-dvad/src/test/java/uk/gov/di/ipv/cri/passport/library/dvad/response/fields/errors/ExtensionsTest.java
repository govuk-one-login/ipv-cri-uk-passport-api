package uk.gov.di.ipv.cri.passport.library.dvad.response.fields.errors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.fields.errors.Extensions;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ExtensionsTest {
    // Extensions tested to ensure Deserialization can handle
    // incoming classification field as object or string

    private static final String ExtensionsWithClassificationObject =
            "{\"classification\": {\"StringField1\":\"StringField1 Value\",\"StringArray\":[\"StringArray1\",\"StringArray2\",\"StringArray3\"],\"constraint\":\"StringField2 Value\"} }";
    private static final String ExpectedResultWithExtensionsWithClassificationObjectInsideString =
            "{\"classification\":\"{\"StringField1\":\"StringField1 Value\",\"StringArray\":[\"StringArray1\",\"StringArray2\",\"StringArray3\"],\"constraint\":\"StringField2 Value\"}\"}";

    private static final ObjectMapper realObjectMapper = new ObjectMapper();

    @Test
    void shouldDeserializeExtensionsWhenClassificationIsObject() throws JsonProcessingException {

        AtomicReference<Extensions> arExtensions = new AtomicReference<>();
        // Simulate Incoming request that has Classification as Object
        assertDoesNotThrow(
                () ->
                        arExtensions.set(
                                realObjectMapper.readValue(
                                        ExtensionsWithClassificationObject, Extensions.class)));

        assertNotNull(arExtensions.get());

        // replaceAll as object mapper will add escape around quotes causing a mismatch
        String extString =
                realObjectMapper.writeValueAsString(arExtensions.get()).replaceAll("\\\\", "");

        // Classification Object is intended to be converted to a string during mapping
        assertEquals(ExpectedResultWithExtensionsWithClassificationObjectInsideString, extString);
    }

    @Test
    void shouldDeserializeExtensionsWhenClassificationIsString() throws JsonProcessingException {

        Extensions incommingExtensions =
                Extensions.builder()
                        .errorCode("An Error Code")
                        .classification("Classification as String")
                        .build();

        String incommingExtensionsAsString =
                realObjectMapper.writeValueAsString(incommingExtensions);

        // Simulate Incoming request that has Classification as String
        AtomicReference<Extensions> arExtensions = new AtomicReference<>();
        assertDoesNotThrow(
                () ->
                        arExtensions.set(
                                realObjectMapper.readValue(
                                        incommingExtensionsAsString, Extensions.class)));

        assertNotNull(arExtensions.get());

        // replaceAll as object mapper will add escape around quotes causing a mismatch
        String extAsString =
                realObjectMapper.writeValueAsString(arExtensions.get()).replaceAll("\\\\", "");

        // Classification Object is intended to be converted to a string during mapping
        assertEquals(incommingExtensionsAsString, extAsString);
    }
}
