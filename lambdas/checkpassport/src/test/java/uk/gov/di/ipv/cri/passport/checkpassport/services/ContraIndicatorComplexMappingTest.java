package uk.gov.di.ipv.cri.passport.checkpassport.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class ContraIndicatorComplexMappingTest {

    @Test
    void shouldCreateContraIndicatorComplexMappingFromSingleCamelFlag() {

        ContraIndicatorComplexMapping ciCM =
                new ContraIndicatorComplexMapping("A01", "flagOne", "1234");

        assertEquals("One", ciCM.getReason());
        assertEquals("one_check", ciCM.getCheck());
        assertEquals("A01", ciCM.getCi());
        assertEquals("1234", ciCM.getRequiredFlagValue());
    }

    @Test
    void shouldCreateContraIndicatorComplexMappingFromDoubleCamelFlag() {
        ContraIndicatorComplexMapping ciCM =
                new ContraIndicatorComplexMapping("B01", "doubleFlagOne", "ABC");

        assertEquals("FlagOne", ciCM.getReason());
        assertEquals("flag_one_check", ciCM.getCheck());
        assertEquals("B01", ciCM.getCi());
        assertEquals("ABC", ciCM.getRequiredFlagValue());
    }

    @Test
    void shouldCreateContraIndicatorComplexMappingFromTripleCamelFlag() {
        ContraIndicatorComplexMapping ciCM =
                new ContraIndicatorComplexMapping("C01", "tripleFlagAbCd", "123ABC++");

        assertEquals("FlagAbCd", ciCM.getReason());
        assertEquals("flag_ab_cd_check", ciCM.getCheck());
        assertEquals("C01", ciCM.getCi());
        assertEquals("123ABC++", ciCM.getRequiredFlagValue());
    }

    @Test
    void shouldThrowExceptionIfFlagIsAllLowerCase() {

        IllegalStateException thrownException =
                assertThrows(
                        IllegalStateException.class,
                        () -> new ContraIndicatorComplexMapping("L01", "abc", "false"));

        assertEquals(
                "Flag abc not in the expected camel case format", thrownException.getMessage());
    }

    @Test
    void shouldThrowExceptionIfFlagIsAllNumeric() {

        IllegalStateException thrownException =
                assertThrows(
                        IllegalStateException.class,
                        () -> new ContraIndicatorComplexMapping("N01", "1234", "false"));

        assertEquals(
                "Flag 1234 not in the expected camel case format", thrownException.getMessage());
    }

    @Test
    void shouldThrowExceptionIfFlagIsTitleCase() {

        IllegalStateException thrownException =
                assertThrows(
                        IllegalStateException.class,
                        () -> new ContraIndicatorComplexMapping("T01", "FlagOne", "false"));

        assertEquals(
                "Flag FlagOne not in the expected camel case format", thrownException.getMessage());
    }
}
