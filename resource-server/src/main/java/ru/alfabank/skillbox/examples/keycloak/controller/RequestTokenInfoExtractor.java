package ru.alfabank.skillbox.examples.keycloak.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class RequestTokenInfoExtractor {

    private final JwtDecoder jwtDecoder;

    public Map<String, Map<String, Object>> get(HttpServletRequest request) {
        String token = new DefaultBearerTokenResolver().resolve(request);
        log.info("Authorization header token: {}", token);
        Jwt jwt = jwtDecoder.decode(token);
        return Map.of(
                "headers", jwt.getHeaders(),
                "claims", jwt.getClaims()
        );
    }
}
