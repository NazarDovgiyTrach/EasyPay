package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

public class NewPasswordDTO {

    @NotEmpty(message = "Current password required")
    private String oldPassword;

    @NotEmpty(message = "Password must contain at least 7 characters!")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{7,}$", message = "Password must contain at " +
            "least one uppercase character, one lowercase character and one digit!")
    private String newPassword;

    public NewPasswordDTO() {
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
