package org.example;

public class RestartException extends RuntimeException {
    public RestartException() {
        super();
    }

    public RestartException(String s) {
        super(s);
    }
}
