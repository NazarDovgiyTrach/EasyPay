package com.softserveinc.ch067.easypay.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class AccountIsBannedException extends BadCredentialsException {

    public AccountIsBannedException(String msg) {
        super(msg);
    }
}
