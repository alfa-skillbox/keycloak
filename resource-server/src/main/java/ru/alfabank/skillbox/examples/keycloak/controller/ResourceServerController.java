package ru.alfabank.skillbox.examples.keycloak.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfabank.skillbox.examples.keycloak.jwt.RequestJwtAuthorizationInfoExtractor;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value = "/resource-server", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class ResourceServerController {

    private final RequestJwtAuthorizationInfoExtractor jwtAuthorizationInfoExtractor;

    @GetMapping("/**")
    public ResponseEntity<?> clientToken(HttpServletRequest request) {
        return ResponseEntity.ok(jwtAuthorizationInfoExtractor.get(request));
    }
}
