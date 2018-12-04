package com.softserveinc.ch067.easypay.exception;

public class ForbiddenCounterActionException extends RuntimeException {
    public ForbiddenCounterActionException(String message) {
        super(message);
    }
}
