package uk.gov.di.ipv.cri.passport.issuecredential.exception;

import java.io.Serial;

public class DocumentCheckResultItemNotFoundException extends Exception {
    @Serial private static final long serialVersionUID = -7399257595290334637L;

    public DocumentCheckResultItemNotFoundException(String message) {
        super(message);
    }
}
