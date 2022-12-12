package ru.alfabank.skillbox.examples.keycloak.config.properties;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;

@Slf4j
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "clients.permit")
public class JwtGrantedAuthoritiesProperties {
    public static final String BY_REALM_ROLE_KEY = "byRealmRole";
    public static final String BY_CLIENT_ROLE_KEY = "byClientRole";
    public static final String BY_CLIENTS_DEFAULT_SCOPE_KEY = "byClientsDefaultScope";
    public static final String BY_CLIENTS_OPTIONAL_SCOPE_KEY = "byClientsOptionalScope";
    public static final String BY_USER_GROUP_KEY = "byUserGroup";
    public static final String BY_CLAIM_KEY = "byClaim";

    @NotEmpty(message = "Property clients.permit.authorities should not be empty")
    private Map<String, AuthorityProperties> authorities;

    public String[] getAllPermittedAuthorities() {
        var values = authorities.entrySet().stream()
                .flatMap(entry ->
                        Stream.of(entry.getValue().getAuthority()))
                .toArray(String[]::new);
        log.info("Permitted authorities: {}", Arrays.toString(values));
        return Arrays.copyOf(values, values.length, String[].class);
    }

    @Data
    public static class AuthorityProperties {
        @NotBlank
        private String claim;
        @NotBlank
        private String prefix;
        @NotBlank
        private String authority;
        @NotBlank
        private String endpoint;

        public String getAuthority() {
            return prefix + authority;
        }
    }
}
