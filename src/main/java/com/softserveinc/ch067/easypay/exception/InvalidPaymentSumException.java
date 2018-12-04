package com.softserveinc.ch067.easypay.exception;

public class InvalidPaymentSumException extends RuntimeException {
    public InvalidPaymentSumException(String message) {
        super(message);
    }
}
