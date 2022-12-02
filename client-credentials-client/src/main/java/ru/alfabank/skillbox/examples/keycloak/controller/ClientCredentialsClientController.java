package ru.alfabank.skillbox.examples.keycloak.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfabank.skillbox.examples.keycloak.restclient.RestClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
@RequestMapping(value = "/client-credentials-client", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class ClientCredentialsClientController {

    private final RestClient restClient;

    @GetMapping("/invoke")
    public ResponseEntity<Map<String, Map<String, Object>>> invoke(Authentication authentication,
                                                      HttpServletRequest request,
                                                      HttpServletResponse response) {
        return restClient.invoke(authentication, request, response);
    }
}
