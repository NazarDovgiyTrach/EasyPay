package com.softserveinc.ch067.easypay.dto;

public class PasswordResetDto {

    private String password;
    private String confirmPassword;

    public PasswordResetDto() {
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}
