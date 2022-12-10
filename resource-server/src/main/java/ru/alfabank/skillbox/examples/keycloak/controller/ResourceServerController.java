package ru.alfabank.skillbox.examples.keycloak.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping(value = "/resource-server", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class ResourceServerController {

    private final RequestTokenInfoExtractor tokenInfoExtractor;

    @GetMapping("/request-headers")
    public ResponseEntity<?> headers(@RequestHeader Map<String, String> headers) {
        return ResponseEntity.ok(headers);
    }

    @GetMapping("/client-token")
    public ResponseEntity<?> clientToken(HttpServletRequest request) {
        return ResponseEntity.ok(tokenInfoExtractor.get(request));
    }
}
