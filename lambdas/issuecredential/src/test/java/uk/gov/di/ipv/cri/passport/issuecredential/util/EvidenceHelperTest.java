package uk.gov.di.ipv.cri.passport.issuecredential.util;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.cri.passport.issuecredential.domain.verifiablecredential.Evidence;
import uk.gov.di.ipv.cri.passport.library.persistence.DocumentCheckResultItem;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class EvidenceHelperTest {

    @Test
    void shouldMapAllFieldsWhenFullyPopulated() {
        DocumentCheckResultItem item = new DocumentCheckResultItem();
        item.setTransactionId("txn-123");
        item.setStrengthScore(4);
        item.setValidityScore(2);
        item.setContraIndicators(List.of("CI01"));
        item.setCheckDetails(List.of("RECORD_CHECK"));
        item.setFailedCheckDetails(List.of("ONLINE_FRAUD_CHECK"));
        item.setCiReasons(List.of("CI01,reason1"));

        Evidence evidence = EvidenceHelper.documentCheckResultItemToEvidence(item);

        assertEquals("IdentityCheck", evidence.getType());
        assertEquals("txn-123", evidence.getTxn());
        assertEquals(4, evidence.getStrengthScore());
        assertEquals(2, evidence.getValidityScore());
        assertEquals(List.of("CI01"), evidence.getCi());
        assertEquals(1, evidence.getCheckDetails().size());
        assertEquals("record_check", evidence.getCheckDetails().get(0).getDataCheck());
        assertEquals(1, evidence.getFailedCheckDetails().size());
        assertEquals("online_fraud_check", evidence.getFailedCheckDetails().get(0).getDataCheck());
        assertEquals(1, evidence.getCiReasons().size());
        assertEquals("CI01", evidence.getCiReasons().get(0).getCi());
        assertEquals("reason1", evidence.getCiReasons().get(0).getReason());
    }

    @Test
    void shouldNotSetCheckDetailsWhenNull() {
        DocumentCheckResultItem item = new DocumentCheckResultItem();
        item.setTransactionId("txn-456");

        Evidence evidence = EvidenceHelper.documentCheckResultItemToEvidence(item);

        assertNull(evidence.getCheckDetails());
        assertNull(evidence.getFailedCheckDetails());
        assertNull(evidence.getCiReasons());
    }

    @Test
    void shouldNotSetCheckDetailsWhenEmpty() {
        DocumentCheckResultItem item = new DocumentCheckResultItem();
        item.setTransactionId("txn-789");
        item.setCheckDetails(List.of());
        item.setFailedCheckDetails(List.of());

        Evidence evidence = EvidenceHelper.documentCheckResultItemToEvidence(item);

        assertNull(evidence.getCheckDetails());
        assertNull(evidence.getFailedCheckDetails());
    }

    @Test
    void shouldHandleMultipleCiReasons() {
        DocumentCheckResultItem item = new DocumentCheckResultItem();
        item.setTransactionId("txn-multi");
        item.setCiReasons(List.of("CI01,reason1", "CI02,reason2"));

        Evidence evidence = EvidenceHelper.documentCheckResultItemToEvidence(item);

        assertEquals(2, evidence.getCiReasons().size());
        assertEquals("CI01", evidence.getCiReasons().get(0).getCi());
        assertEquals("reason1", evidence.getCiReasons().get(0).getReason());
        assertEquals("CI02", evidence.getCiReasons().get(1).getCi());
        assertEquals("reason2", evidence.getCiReasons().get(1).getReason());
    }
}
