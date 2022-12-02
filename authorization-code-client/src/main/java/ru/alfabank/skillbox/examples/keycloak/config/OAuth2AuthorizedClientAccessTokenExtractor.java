package ru.alfabank.skillbox.examples.keycloak.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import javax.servlet.http.HttpServletRequest;

@FunctionalInterface
public interface OAuth2AuthorizedClientAccessTokenExtractor {

    String getToken(HttpServletRequest request, Authentication authentication);
}
