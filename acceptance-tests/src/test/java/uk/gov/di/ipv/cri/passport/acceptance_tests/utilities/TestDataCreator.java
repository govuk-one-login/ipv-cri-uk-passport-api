package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

import java.util.HashMap;
import java.util.Map;

public class TestDataCreator {

    public static Map<String, TestInput> passportTestUsers = new HashMap<>();

    public static PassportSubject kennethHappyPath;
    public static PassportSubject selinaUnhappyPath;

    public static TestInput getPassportTestUserFromMap(String scenario) {
        return passportTestUsers.get(scenario);
    }

    public static void createDefaultResponses() {
        kennethHappyPath =
                new PassportSubject(
                        "321654987",
                        "DECERQUEIRA",
                        "KENNETH",
                        "",
                        "08",
                        "07",
                        "1965",
                        "01",
                        "10",
                        "2042");
        selinaUnhappyPath =
                new PassportSubject(
                        "88776655", "KYLE", "SELINA", "", "12", "08", "1985", "04", "08", "2032");

        passportTestUsers.put("PassportSubjectHappyKenneth", kennethHappyPath);
        passportTestUsers.put("PassportSubjectUnhappySelina", selinaUnhappyPath);
    }
}
