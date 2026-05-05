package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class ObjectMapperFactory {
    public static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());

    private ObjectMapperFactory() {}
}
