package com.softserveinc.ch067.easypay.exception;

import io.jsonwebtoken.JwtException;

public class ConfirmRegistrationJWTInvalidException extends JwtException {
    public ConfirmRegistrationJWTInvalidException(String message) {
        super(message);
    }
}
