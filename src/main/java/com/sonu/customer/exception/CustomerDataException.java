package com.sonu.customer.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class CustomerDataException extends RuntimeException {

    public CustomerDataException(String message) {
        super(message);
    }

    public CustomerDataException(Exception ex) {
        super(ex);
    }

}
