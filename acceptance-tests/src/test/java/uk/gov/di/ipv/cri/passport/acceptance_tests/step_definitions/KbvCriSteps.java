package uk.gov.di.ipv.cri.passport.acceptance_tests.step_definitions;

import io.cucumber.java.en.And;
import uk.gov.di.ipv.cri.passport.acceptance_tests.pages.*;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.fail;

public class KbvCriSteps {
    private final KbvQuestionPage kbvQuestionPage = new KbvQuestionPage();
    private final OrchestratorStubPage orchestratorStubPage =
        new OrchestratorStubPage();
    private final String SUCCESSFULLY = "Successfully";
    private final String UNSUCCESSFULLY = "Unsuccessfully";

    @And("the user {string} {string} passes the KBV CRI Check")
    public void theUserSuccessfullyPassesKBVCRICheck(String userName, String kbvQuestionSuccess)
            throws IOException {
        orchestratorStubPage.continueButton.click();
        if (kbvQuestionSuccess.equals(SUCCESSFULLY)) {
            int SUCCESSFUL_KBV_QUESTION_COUNT = 3;
            for (int i = 0; i < SUCCESSFUL_KBV_QUESTION_COUNT; i++) {
                kbvQuestionPage.answerKbvQuestion(kbvQuestionSuccess, userName);
            }
        } else if (kbvQuestionSuccess.equals(UNSUCCESSFULLY)) {
            int UNSUCCESSFUL_KBV_QUESTION_COUNT = 2;
            for (int i = 0; i < UNSUCCESSFUL_KBV_QUESTION_COUNT; i++) {
                kbvQuestionPage.answerKbvQuestion(kbvQuestionSuccess, userName);
            }
        } else {
            fail(
                    "Valid KBV Option not selected in BDD Statement. Possible Values: Successfully, Unsuccessfully");
        }
    }
}
