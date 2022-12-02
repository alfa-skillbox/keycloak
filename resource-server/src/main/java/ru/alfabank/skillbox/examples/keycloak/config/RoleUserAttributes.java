package ru.alfabank.skillbox.examples.keycloak.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class RoleUserAttributes {

    @JsonProperty("resource_access")
    private Map<String, Roles> resourceAccess;

    public List<String> getFirstClientRoles() {
        return Optional.ofNullable(resourceAccess)
                .filter(map -> !map.isEmpty())
                .map(Map::values)
                .map(this::combineAllRoles)
                .orElseGet(List::of);
    }

    private List<String> combineAllRoles(Collection<Roles> rolesList) {
        return rolesList.stream()
                .map(Roles::getRoles)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }

    @Data
    private static class Roles {
        private List<String> roles;
    }
}
