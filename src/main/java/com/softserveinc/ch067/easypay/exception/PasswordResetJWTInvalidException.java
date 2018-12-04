package com.softserveinc.ch067.easypay.exception;

import io.jsonwebtoken.JwtException;

public class PasswordResetJWTInvalidException extends JwtException {
    public PasswordResetJWTInvalidException(String message) {
        super(message);
    }
}
