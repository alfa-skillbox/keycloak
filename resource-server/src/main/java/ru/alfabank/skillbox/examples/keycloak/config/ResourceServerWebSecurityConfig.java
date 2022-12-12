package ru.alfabank.skillbox.examples.keycloak.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import ru.alfabank.skillbox.examples.keycloak.config.authorities.JwtGrantedAuthoritiesConverterDelegator;
import ru.alfabank.skillbox.examples.keycloak.config.properties.JwtGrantedAuthoritiesProperties;

@Slf4j
@Configuration
@EnableConfigurationProperties(JwtGrantedAuthoritiesProperties.class)
@RequiredArgsConstructor
public class ResourceServerWebSecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/actuator/**");
    }

    @Bean
    public SecurityFilterChain resourceServerSpringSecurityFilterChain(
            HttpSecurity http,
            JwtGrantedAuthoritiesProperties authoritiesProperties) throws Exception {
        // @formatter:off
        http
                // who can come in
                .requestMatchers(rmConfigurer -> rmConfigurer.antMatchers("/resource-server/**"))
                .csrf().disable()
                .authorizeRequests(customizer -> authorizeRequestCustomizer(customizer, authoritiesProperties))
                .exceptionHandling().accessDeniedHandler(new AccessDeniedHandlerImpl())
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(getJwtAuthenticationConverter(authoritiesProperties));

        // @formatter:on
        return http.build();
    }

    public void authorizeRequestCustomizer(
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry,
            JwtGrantedAuthoritiesProperties authoritiesProperties) {
        authoritiesProperties.getAuthorities().forEach((key, authorityProperties) ->
                registry.antMatchers(authorityProperties.getEndpoint()).hasAuthority(authorityProperties.getAuthority()));
        registry.anyRequest().denyAll();
    }

    @Bean
    public JwtAuthenticationConverter getJwtAuthenticationConverter(
            JwtGrantedAuthoritiesProperties authoritiesProperties) {
        var jwtAuthenticationConverter = new JwtAuthenticationConverter();
        var jwtAuthorizationConverter = new JwtGrantedAuthoritiesConverterDelegator();
        // add out-of-the-box scope authorities converter
        jwtAuthorizationConverter.addConverter(new JwtGrantedAuthoritiesConverter());

        authoritiesProperties.getAuthorities().forEach((key, authorityProperties) -> {
            var prefix = authorityProperties.getPrefix();
            if ("SCOPE_".equals(prefix)) {
                // they are already added in pure JwtGrantedAuthoritiesConverter
                return;
            }
            var claim = authorityProperties.getClaim();
            var authorizationConverter = new JwtGrantedAuthoritiesConverter();
            authorizationConverter.setAuthoritiesClaimName(claim);
            authorizationConverter.setAuthorityPrefix(prefix);
            jwtAuthorizationConverter.addConverter(authorizationConverter);
            log.info("JwtGrantedAuthoritiesConverter for claim {} with prefix {} was added", claim, prefix);
        });

        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtAuthorizationConverter);
        return jwtAuthenticationConverter;
    }
}
