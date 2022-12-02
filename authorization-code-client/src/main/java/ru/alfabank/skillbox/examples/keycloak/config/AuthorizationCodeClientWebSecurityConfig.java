package ru.alfabank.skillbox.examples.keycloak.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Configuration
public class AuthorizationCodeClientWebSecurityConfig {

    @Bean
    public SecurityFilterChain authorizationCodeSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                // who can come in
                .requestMatchers(rmConfigurer -> rmConfigurer.antMatchers("/authorization-code-client/**",
                        "/oauth2/**", "/login/**"))
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/oauth2/**", "/login/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().accessDeniedHandler(new AccessDeniedHandlerImpl())
                .and()
                .oauth2Login()
                .defaultSuccessUrl("/authorization-code-client/invoke")
                .and()
                .logout();
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
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .refreshToken()
                        .authorizationCode()
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        return authorizedClientManager;
    }

    @Bean
    public OAuth2AuthorizedClientAccessTokenExtractor accessTokenExtractor(OAuth2AuthorizedClientManager authorizedClientManager) {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            var registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
                    .principal(authentication)
                    .attributes(attrs -> {
                        attrs.put(HttpServletRequest.class.getName(), request);
                        attrs.put(HttpServletResponse.class.getName(), response);
                    })
                    .build();
            return Optional.ofNullable(authorizedClientManager.authorize(authorizeRequest))
                    .map(authorizedClient -> {
                        String access_token = StringUtils.EMPTY;
                        if (authorizedClient.getRefreshToken() != null) {
                            log.info("Refresh token: {}", authorizedClient.getRefreshToken().getTokenValue());
                        }
                        if (authorizedClient.getAccessToken() != null) {
                            access_token = authorizedClient.getAccessToken().getTokenValue();
                            log.info("Access token: {}", access_token);
                            if (authorizedClient.getAccessToken().getExpiresAt() != null) {
                                log.info("Access expired?: {}", authorizedClient.getAccessToken().getExpiresAt().isBefore(Instant.now()));
                            }
                        }
                        return access_token;
                    })
                    .orElse(StringUtils.EMPTY);
        };
    }
}
