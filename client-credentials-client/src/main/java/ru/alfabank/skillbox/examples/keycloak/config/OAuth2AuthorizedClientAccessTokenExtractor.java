package ru.alfabank.skillbox.examples.keycloak.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@FunctionalInterface
public interface OAuth2AuthorizedClientAccessTokenExtractor {

    String getToken(HttpServletRequest request, HttpServletResponse response);
}
