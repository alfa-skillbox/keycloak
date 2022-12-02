package ru.alfabank.skillbox.examples.keycloak.restclient;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public interface RestClient {

    ResponseEntity<Map<String, Map<String, Object>>> invoke(Authentication authentication, HttpServletRequest request);
}
