package ru.alfabank.skillbox.examples.keycloak.config.authorities;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
public class JwtGrantedAuthoritiesConverterDelegator implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final List<Converter<Jwt, Collection<GrantedAuthority>>> delegates = new ArrayList<>();

    public void addConverter(Converter<Jwt, Collection<GrantedAuthority>> converter) {
        delegates.add(converter);
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Converter<Jwt, Collection<GrantedAuthority>> converter : delegates) {
            Collection<GrantedAuthority> result = converter.convert(source);
            if (result != null) {
                log.info("Created new Granted Authorities: {}", result);
                grantedAuthorities.addAll(result);
            }
        }
        log.info("All Granted Authorities: {}", grantedAuthorities);
        return grantedAuthorities;
    }
}
