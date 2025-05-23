package uk.gov.di.ipv.cri.passport.issuecredential.exception;

import java.io.Serial;

public class SessionItemNotFoundException extends Exception {
    @Serial private static final long serialVersionUID = 3325731229399706021L;

    public SessionItemNotFoundException(String message) {
        super(message);
    }
}
