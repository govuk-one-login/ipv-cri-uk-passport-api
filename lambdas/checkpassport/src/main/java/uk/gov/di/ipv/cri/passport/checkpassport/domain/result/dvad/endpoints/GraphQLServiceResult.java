package uk.gov.di.ipv.cri.passport.checkpassport.domain.result.dvad.endpoints;

import lombok.Builder;
import lombok.Data;
import uk.gov.di.ipv.cri.passport.checkpassport.domain.response.dvad.GraphQLAPIResponse;

@Builder
@Data
public class GraphQLServiceResult {
    private final GraphQLAPIResponse graphQLAPIResponse;
    private final String requestId;
}
