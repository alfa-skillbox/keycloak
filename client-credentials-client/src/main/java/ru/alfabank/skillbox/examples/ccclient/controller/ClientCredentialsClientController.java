package ru.alfabank.skillbox.examples.ccclient.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alfabank.skillbox.examples.ccclient.dto.Response;
import ru.alfabank.skillbox.examples.ccclient.restclient.RestClient;

@RestController
@RequestMapping(value = "/client-credentials-client", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class ClientCredentialsClientController {
    private final RestClient ccClient;

    @GetMapping("/invoke")
    public ResponseEntity<Response> invoke() {
        return ResponseEntity.ok(ccClient.invoke());
    }
}
