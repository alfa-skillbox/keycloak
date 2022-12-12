package ru.alfabank.skillbox.examples.ccclient.restclient;

import ru.alfabank.skillbox.examples.ccclient.dto.Response;

public interface RestClient {

    Response invoke(String path);

}
