package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

public class ContinueUserRegistrationDTO {

    @NotEmpty(message = "Name must contain at least 2 characters!")
    @Pattern(regexp = "^[A-Z][a-z]{1,30}([\\-][A-Z][a-z]{1,30}|)$",
            message = "Name can contain only latin letters and - sign!")
    private String name;

    @NotEmpty(message = "Surname must contain at least 2 characters!")
    @Pattern(regexp = "^[A-Z][a-z]{1,30}([\\-][A-Z][a-z]{1,30}|)$",
            message = "Surname can contain only latin letters and - sign!")
    private String surname;

    @NotEmpty(message = "Phone number is required!")
    @Pattern(regexp = "^\\+(\\d{12})$", message = "Enter valid phone number!")
    private String phoneNumber;

    public ContinueUserRegistrationDTO() {
    }

    public ContinueUserRegistrationDTO(@NotEmpty(message = "Name must contain at least 2 characters!")
                                       @Pattern(regexp = "^[A-Z][a-z]{1,30}([\\-][A-Z][a-z]{1,30}|)$",
                                               message = "Name can contain only latin letters and - sign!") String name,
                                       @NotEmpty(message = "Surname must contain at least 2 characters!")
                                       @Pattern(regexp = "^[A-Z][a-z]{1,30}([\\-][A-Z][a-z]{1,30}|)$",
                                               message = "Surname can contain only latin letters and - sign!") String surname,
                                       @NotEmpty(message = "Password must contain at least 7 characters!") String password,
                                       @NotEmpty(message = "Phone number is required!")
                                       @Pattern(regexp = "^\\+(\\d{12})$",
                                               message = "Enter valid phone number!") String phoneNumber) {
        this.name = name;
        this.surname = surname;
        this.phoneNumber = phoneNumber;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }
}
