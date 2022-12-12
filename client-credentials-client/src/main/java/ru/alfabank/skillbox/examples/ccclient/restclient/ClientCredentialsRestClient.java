package ru.alfabank.skillbox.examples.ccclient.restclient;

import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import ru.alfabank.skillbox.examples.ccclient.config.OAuth2AuthorizedClientAccessTokenExtractor;
import ru.alfabank.skillbox.examples.ccclient.dto.Response;

import java.net.URI;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Slf4j
@Setter
@Component
@RequiredArgsConstructor
public class ClientCredentialsRestClient implements RestClient {
    private final RestTemplate restTemplate;
    private final OAuth2AuthorizedClientAccessTokenExtractor accessTokenExtractor;

    @Value("${spring.security.oauth2.client.registration.cc-client.registrationId}")
    private String registrationId;
    @Value("${spring.security.oauth2.client.registration.cc-client.client-id}")
    private String clientId;

    @Value("${rest.clients.cc-client.uri}")
    private String uri;

    @Override
    public Response invoke(String path) {
        String accessToken = accessTokenExtractor.getToken(registrationId, clientId);
        log.info("Access token: {}", accessToken);
        try {
            ResponseEntity<Object> resourceResponse = getResponse(path, accessToken);
            return Response.builder()
                    .status(resourceResponse.getStatusCode().name())
                    .body(resourceResponse.getBody())
                    .error(Response.Error.builder().build())
                    .build();
        } catch (HttpClientErrorException.Unauthorized e) {
            // 401 response returned
            log.error("401 occur! {}", e.getLocalizedMessage());
            // get new access_token
            accessToken = accessTokenExtractor.getToken(registrationId, clientId);
            // repeat exchange
            ResponseEntity<Object> resourceResponse = getResponse(path, accessToken);
            return Response.builder()
                    .status(resourceResponse.getStatusCode().name())
                    .body(resourceResponse.getBody())
                    .error(Response.Error.builder()
                            .code(e.getStatusCode().name())
                            .message("Client '" + clientId + "' authentication problem occur. " + e.getResponseBodyAsString())
                            .build())
                    .build();
        } catch (HttpStatusCodeException hsce) {
            // HTTP 4xx is received
            log.error("4xx occur! {}", hsce.getLocalizedMessage());
            return Response.builder()
                    .status(INTERNAL_SERVER_ERROR.name())
                    .error(Response.Error.builder()
                            .code(hsce.getStatusCode().name())
                            .message("Client '" + clientId + "' 1xx - 5xx problem occur. " + hsce.getResponseBodyAsString())
                            .build())
                    .build();
        } catch (RestClientException rce) {
            // Other cases
            log.error("Some exception occur during rest connection! {}", rce.getLocalizedMessage());
            return Response.builder()
                    .status(INTERNAL_SERVER_ERROR.name())
                    .error(Response.Error.builder()
                            .message("Client '" + clientId + "' problem occur. " + rce.getLocalizedMessage())
                            .build())
                    .build();
        }
    }

    private ResponseEntity<Object> getResponse(String path, String accessToken) {
        return restTemplate.exchange(RequestEntity
                        .get(URI.create(uri + path))
                        .header(AUTHORIZATION, "Bearer " + accessToken)
                        .accept(MediaType.APPLICATION_JSON).build(),
                new ParameterizedTypeReference<>() {
                });
    }
}
