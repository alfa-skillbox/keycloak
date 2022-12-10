package ru.alfabank.skillbox.examples.ccclient.config;

@FunctionalInterface
public interface OAuth2AuthorizedClientAccessTokenExtractor {

    String getToken(String registrationId, String clientId);
}
