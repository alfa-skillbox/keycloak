package ru.alfabank.skillbox.examples.keycloak.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
public final class RoleUserJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.registerModule(new JavaTimeModule());
    }

    private static final String ROLE_PREFIX = "ROLE_";

    /**
     * Extract {@link GrantedAuthority}s from the given {@link Jwt}.
     *
     * @param jwt The {@link Jwt} token
     * @return The {@link GrantedAuthority authorities} read from the token scopes
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        getResourceAccessMap(jwt.getClaims())
                .forEach(authority ->
                        grantedAuthorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + authority)));
        return grantedAuthorities;
    }

    @SneakyThrows
    private List<String> getResourceAccessMap(Object clientIdClaimObj) {
        return MAPPER.readValue(MAPPER.writeValueAsBytes(clientIdClaimObj), RoleUserAttributes.class)
                .getFirstClientRoles();
    }
}
