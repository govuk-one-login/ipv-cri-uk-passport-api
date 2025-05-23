package uk.gov.di.ipv.cri.passport.issuecredential.exception;

import java.io.Serial;

public class PersonIdentityDetailedNotFoundException extends Exception {
    @Serial private static final long serialVersionUID = 2806354927766149300L;

    public PersonIdentityDetailedNotFoundException(String message) {
        super(message);
    }
}
