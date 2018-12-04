package com.softserveinc.ch067.easypay.response;

import java.beans.Transient;
import java.util.Map;
import java.util.Objects;

public class VerifyUserResponse {

    private String name;
    private String surname;
    private String phoneNumber;
    private String email;
    private String password;

    public VerifyUserResponse() {
    }

    public VerifyUserResponse(String name, String surname, String phoneNumber, String email, String password) {
        this.name = name;
        this.surname = surname;
        this.phoneNumber = phoneNumber;
        this.email = email;
        this.password = password;
    }

    public VerifyUserResponse(Map<String, String> messages){
        this.name = messages.get("name");
        this.surname = messages.get("surname");
        this.phoneNumber = messages.get("phoneNumber");
        this.email = messages.get("email");
        this.password = messages.get("password");
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

    @Transient
    public boolean isValid(){
        return this.name == null && this.surname == null && this.phoneNumber == null &&
                this.email == null && this.password == null;
    }

    @Override
    public String toString() {
        return "VerifyUserResponse{" +
                "name='" + name + '\'' +
                ", surname='" + surname + '\'' +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof VerifyUserResponse)) return false;
        VerifyUserResponse that = (VerifyUserResponse) o;
        return Objects.equals(name, that.name) &&
                Objects.equals(surname, that.surname) &&
                Objects.equals(phoneNumber, that.phoneNumber) &&
                Objects.equals(email, that.email) &&
                Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, surname, phoneNumber, email, password);
    }
}
