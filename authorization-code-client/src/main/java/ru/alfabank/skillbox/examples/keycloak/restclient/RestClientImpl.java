package ru.alfabank.skillbox.examples.keycloak.restclient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import ru.alfabank.skillbox.examples.keycloak.config.OAuth2AuthorizedClientAccessTokenExtractor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Component
@RequiredArgsConstructor
public class RestClientImpl implements RestClient {
    private final RestTemplate restTemplate;
    private final OAuth2AuthorizedClientAccessTokenExtractor accessTokenExtractor;

    public ResponseEntity<Map<String, Map<String, Object>>> invoke(Authentication authentication,
                                                                   HttpServletRequest request,
                                                                   HttpServletResponse response) {
        var accessToken = accessTokenExtractor.getToken(request, response, authentication);
        ResponseEntity<Map<String, Map<String, Object>>> resourceResponse;
        try {
            resourceResponse = getExchange(accessToken);
        } catch (HttpClientErrorException.Unauthorized e) {
            // 401 response returned
            log.error("401 occur! {}", e.getLocalizedMessage());
            // get new access_token
            accessToken = accessTokenExtractor.getToken(request, response, null);
            // repeat exchange
            resourceResponse = getExchange(accessToken);
        }
        log.info("Server response: {}", resourceResponse.getBody());
        return resourceResponse;
    }

    private ResponseEntity<Map<String, Map<String, Object>>> getExchange(String accessToken) {
        return restTemplate.exchange(RequestEntity
                        .get(URI.create("http://localhost:8083/resource-server/client-token"))
                        .header(AUTHORIZATION, "Bearer " + accessToken)
                        .accept(MediaType.APPLICATION_JSON).build(),
                new ParameterizedTypeReference<>() {
                });
    }
}
