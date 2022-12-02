package ru.alfabank.skillbox.examples.keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
public class ClientCredentialsClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientCredentialsClientApplication.class, args);
    }

}