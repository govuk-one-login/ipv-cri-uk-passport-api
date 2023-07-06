package uk.gov.di.ipv.cri.passport.checkpassport.services;

import uk.gov.di.ipv.cri.passport.checkpassport.domain.result.ThirdPartyAPIResult;
import uk.gov.di.ipv.cri.passport.library.domain.PassportFormData;
import uk.gov.di.ipv.cri.passport.library.exceptions.OAuthErrorResponseException;

public interface ThirdPartyAPIService {
    String getServiceName();

    ThirdPartyAPIResult performCheck(PassportFormData passportFormData)
            throws OAuthErrorResponseException;
}
