package uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class ContraIndicatorMapperResult {
    // Prevent these from ever being null
    @Builder.Default private List<String> contraIndicators = new ArrayList<>();

    @Builder.Default private List<String> contraIndicatorReasons = new ArrayList<>();

    @Builder.Default private List<String> contraIndicatorChecks = new ArrayList<>();

    @Builder.Default private List<String> contraIndicatorFailedChecks = new ArrayList<>();
}
