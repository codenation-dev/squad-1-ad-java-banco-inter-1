package br.com.challenge.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class NoContentException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public NoContentException(String msg) {
        super(msg);
    }

    public NoContentException(String msg, Throwable cause) {
        super(msg, cause);
    }
}