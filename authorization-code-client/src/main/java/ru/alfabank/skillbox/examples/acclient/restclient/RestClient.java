package ru.alfabank.skillbox.examples.acclient.restclient;

import org.springframework.security.core.Authentication;
import ru.alfabank.skillbox.examples.acclient.dto.Response;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface RestClient {

    Response invoke(HttpServletRequest request,
                    HttpServletResponse response,
                    Authentication authentication);
}
