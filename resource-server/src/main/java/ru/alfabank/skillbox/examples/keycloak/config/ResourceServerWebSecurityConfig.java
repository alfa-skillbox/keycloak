package ru.alfabank.skillbox.examples.keycloak.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ResourceServerWebSecurityConfig {

    @Value("${clients.permit.authorities.ac-client}")
    private String acClientRole;
    @Value("${clients.permit.authorities.cc-client}")
    private String ccClientRole;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/actuator/**");
    }

    @Bean
    public SecurityFilterChain resourceServerSpringSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                // who can come in
                .requestMatchers(rmConfigurer -> rmConfigurer.antMatchers("/resource-server/**"))
                .csrf().disable()
                .authorizeRequests(customizer -> customizer
                        .antMatchers("/resource-server/client-token").hasAnyAuthority(acClientRole, ccClientRole)
                        .anyRequest().authenticated())
                .exceptionHandling().accessDeniedHandler(new AccessDeniedHandlerImpl())
                .and()
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(getJwtAuthenticationConverter());
        // @formatter:on
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter getJwtAuthenticationConverter() {
        var jwtAuthenticationConverter = new JwtAuthenticationConverter();
        var jwtAuthorizationConverter = new JwtGrantedAuthoritiesConverterDelegator();
        jwtAuthorizationConverter.addConverter(new JwtGrantedAuthoritiesConverter());
        jwtAuthorizationConverter.addConverter(new RoleUserJwtGrantedAuthoritiesConverter());
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtAuthorizationConverter);
        return jwtAuthenticationConverter;
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
