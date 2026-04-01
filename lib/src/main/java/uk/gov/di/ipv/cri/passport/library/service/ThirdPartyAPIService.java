package uk.gov.di.ipv.cri.passport.library.service;

import uk.gov.account.ipv.cri.lime.limeade.strategy.Strategy;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

public interface ThirdPartyAPIService {
    String getServiceName();

    ThirdPartyAPIResult performCheck(PassportFormData passportFormData, Strategy strategy)
            throws OAuthErrorResponseException;
}
