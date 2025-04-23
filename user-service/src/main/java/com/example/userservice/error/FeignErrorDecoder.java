package com.example.userservice.error;

import feign.Response;
import feign.codec.ErrorDecoder;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class FeignErrorDecoder implements ErrorDecoder {

    Environment env;

    public FeignErrorDecoder(Environment env){
        this.env = env;
    }

    @Override
    public Exception decode(String methodName, Response response) {
        return switch (response.status()) {
            case 400 -> {
                if (methodName.contains("getOrders")) {
                    yield new ResponseStatusException(HttpStatus.valueOf(response.status()),
                            "Bad Request");
                }
                yield new ResponseStatusException(HttpStatus.BAD_REQUEST, response.reason());
            }
            case 403 -> {
                if (methodName.contains("getOrders")) {
                    yield new ResponseStatusException(HttpStatus.valueOf(response.status()),
                            "UnAuthorization");
                }
                yield new ResponseStatusException(HttpStatus.FORBIDDEN, response.reason());
            }
            case 404 -> {
                if (methodName.contains("getOrders")) {
                    yield new ResponseStatusException(HttpStatus.NOT_FOUND,
                            env.getProperty("order-service.exception.orders_is_empty"));
                }
                yield new ResponseStatusException(HttpStatus.NOT_FOUND, response.reason());
            }
            default -> new Exception(response.reason());
        };
    }
}
