package br.com.challenge.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class UsersDisabledException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UsersDisabledException() {
        super();
    }
}