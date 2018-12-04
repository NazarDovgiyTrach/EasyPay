package com.softserveinc.ch067.easypay.response;

import com.softserveinc.ch067.easypay.model.UserStatus;

import java.util.Objects;

public class AuthorizationResponse {

    private UserStatus status;
    private String message;

    public AuthorizationResponse(UserStatus status){
        this.status = status;
        this.message = "";
    }

    public AuthorizationResponse(UserStatus status, String message) {
        this.status = status;
        this.message = message;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "AuthorizationResponse{" +
                "status=" + status +
                ", message='" + message + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationResponse that = (AuthorizationResponse) o;
        return status == that.status &&
                Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, message);
    }
}
