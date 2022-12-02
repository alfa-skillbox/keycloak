package ru.alfabank.skillbox.examples.keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
public class AuthorizationCodeClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationCodeClientApplication.class, args);
    }

}