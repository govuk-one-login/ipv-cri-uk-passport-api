package uk.gov.di.ipv.cri.passport.library.dvad.domain.result.endpoints;

import lombok.Builder;
import lombok.Data;
import uk.gov.di.ipv.cri.passport.library.dvad.domain.response.GraphQLAPIResponse;

@Builder
@Data
public class GraphQLServiceResult {
    private final GraphQLAPIResponse graphQLAPIResponse;
    private final String requestId;
}
