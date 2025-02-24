package uk.gov.di.ipv.cri.passport.checkpassport.domain.result.fields;

import java.util.ArrayList;
import java.util.List;

public record ContraIndicatorMapperResult(
        List<String> contraIndicators,
        List<String> contraIndicatorReasons,
        List<String> contraIndicatorChecks,
        List<String> contraIndicatorFailedChecks) {

    public static ContraIndicatorMapperResultBuilder builder() {
        return new ContraIndicatorMapperResultBuilder();
    }

    public static class ContraIndicatorMapperResultBuilder {
        private List<String> contraIndicators;
        private List<String> contraIndicatorReasons;
        private List<String> contraIndicatorChecks;
        private List<String> contraIndicatorFailedChecks;

        private ContraIndicatorMapperResultBuilder() {
            // Intended
        }

        public ContraIndicatorMapperResultBuilder contraIndicators(List<String> contraIndicators) {
            this.contraIndicators = contraIndicators;
            return this;
        }

        public ContraIndicatorMapperResultBuilder contraIndicatorReasons(
                List<String> contraIndicatorReasons) {
            this.contraIndicatorReasons = contraIndicatorReasons;
            return this;
        }

        public ContraIndicatorMapperResultBuilder contraIndicatorChecks(
                List<String> contraIndicatorChecks) {
            this.contraIndicatorChecks = contraIndicatorChecks;
            return this;
        }

        public ContraIndicatorMapperResultBuilder contraIndicatorFailedChecks(
                List<String> contraIndicatorFailedChecks) {
            this.contraIndicatorFailedChecks = contraIndicatorFailedChecks;
            return this;
        }

        public ContraIndicatorMapperResult build() {

            // Prevent these lists from ever being null
            if (null == contraIndicators) {
                contraIndicators = new ArrayList<>();
            }

            if (null == contraIndicatorReasons) {
                contraIndicatorReasons = new ArrayList<>();
            }

            if (null == contraIndicatorChecks) {
                contraIndicatorChecks = new ArrayList<>();
            }

            if (null == contraIndicatorFailedChecks) {
                contraIndicatorFailedChecks = new ArrayList<>();
            }

            return new ContraIndicatorMapperResult(
                    contraIndicators,
                    contraIndicatorReasons,
                    contraIndicatorChecks,
                    contraIndicatorFailedChecks);
        }
    }
}
