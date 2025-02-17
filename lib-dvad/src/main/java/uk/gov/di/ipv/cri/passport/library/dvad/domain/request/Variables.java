package uk.gov.di.ipv.cri.passport.library.dvad.domain.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public record Variables(@JsonProperty(value = "input", required = true) Input input) {}
