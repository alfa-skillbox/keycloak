package ru.alfabank.skillbox.examples.ccclient.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@Configuration
public class ClientCredentialsClientWebSecurityConfig {

    @Bean
    public SecurityFilterChain clientCredentialsSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .requestMatchers().antMatchers("/client-credentials-client/**")
                .and()
                .csrf().disable();
        // @formatter:on
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/actuator/**");
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .clientCredentials()
                        .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        return authorizedClientManager;
    }

    @Bean
    public OAuth2AuthorizedClientAccessTokenExtractor accessTokenExtractor(
            OAuth2AuthorizedClientManager authorizedClientManager) {
        return (registrationId, clientId) -> {
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
                    .principal(clientId)
                    .build();
            return Optional.ofNullable(authorizedClientManager.authorize(authorizeRequest))
                    .map(OAuth2AuthorizedClient::getAccessToken)
                    .map(accessToken -> {
                        var tokenValue = accessToken.getTokenValue();
                        log.info("Access token: {}", tokenValue);
                        if (accessToken.getExpiresAt() != null) {
                            log.info("Access token expired?: {}", accessToken.getExpiresAt().isBefore(Instant.now()));
                        }
                        return tokenValue;
                    })
                    .orElse(StringUtils.EMPTY);
        };
    }
}
