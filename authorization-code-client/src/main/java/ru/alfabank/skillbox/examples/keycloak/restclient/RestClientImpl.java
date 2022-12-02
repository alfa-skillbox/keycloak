package ru.alfabank.skillbox.examples.keycloak.restclient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import ru.alfabank.skillbox.examples.keycloak.config.OAuth2AuthorizedClientAccessTokenExtractor;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@Component
@RequiredArgsConstructor
public class RestClientImpl implements RestClient {
    private final RestTemplate restTemplate;
    private final OAuth2AuthorizedClientAccessTokenExtractor accessTokenExtractor;

    public ResponseEntity<Map<String, Map<String, Object>>> invoke(Authentication authentication, HttpServletRequest request) {
        var accessToken = accessTokenExtractor.getToken(request, authentication);
        log.info("Access token: {}", accessToken);
        ResponseEntity<Map<String, Map<String, Object>>> response = restTemplate.exchange(RequestEntity
                        .get(URI.create("http://localhost:8083/resource-server/client-token"))
                        .header(AUTHORIZATION, "Bearer " + accessToken)
                        .accept(MediaType.APPLICATION_JSON).build(),
                new ParameterizedTypeReference<>() {});
        log.info("Server response: {}", response.getBody());
        return response;
    }
}
