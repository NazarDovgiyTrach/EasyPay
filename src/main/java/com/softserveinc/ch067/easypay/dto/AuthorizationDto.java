package com.softserveinc.ch067.easypay.dto;

public class AuthorizationDto {
    private String email;
    private String password;

    public AuthorizationDto() {
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
