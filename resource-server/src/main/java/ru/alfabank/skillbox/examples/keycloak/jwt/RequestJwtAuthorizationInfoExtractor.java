package ru.alfabank.skillbox.examples.keycloak.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class RequestJwtAuthorizationInfoExtractor {

    private final JwtDecoder jwtDecoder;

    public Map<String, Map<String, Object>> get(HttpServletRequest request) {
        String token = new DefaultBearerTokenResolver().resolve(request);
        if (StringUtils.isNoneBlank(token)) {
            log.info("Authorization header token: {}", token);
            Jwt jwt = jwtDecoder.decode(token);
            return Map.of(
                    "headers", jwt.getHeaders(),
                    "claims", jwt.getClaims()
            );
        }
        throw new IllegalArgumentException("Authorization info is not available. Maybe token is not correct or absent");
    }
}
