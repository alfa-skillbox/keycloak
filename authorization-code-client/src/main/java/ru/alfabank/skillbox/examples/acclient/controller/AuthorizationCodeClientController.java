package ru.alfabank.skillbox.examples.acclient.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfabank.skillbox.examples.acclient.dto.Response;
import ru.alfabank.skillbox.examples.acclient.restclient.AuthorizationCodeRestClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
@RequestMapping(value = "/authorization-code-client", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class AuthorizationCodeClientController {

    private final AuthorizationCodeRestClient restClient;

    @GetMapping("/invoke/{resource-path}")
    public ResponseEntity<Response> invoke(@PathVariable("resource-path") String path,
                                           HttpServletRequest request,
                                           HttpServletResponse response,
                                           Authentication authentication) {
        return ResponseEntity.ok(restClient.invoke(request, response, authentication, path));
    }
}
