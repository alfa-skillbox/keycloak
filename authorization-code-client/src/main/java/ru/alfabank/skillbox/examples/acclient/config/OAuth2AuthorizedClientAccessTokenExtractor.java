package ru.alfabank.skillbox.examples.acclient.config;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@FunctionalInterface
public interface OAuth2AuthorizedClientAccessTokenExtractor {

    String getToken(HttpServletRequest request, HttpServletResponse response, Authentication authentication);
}
