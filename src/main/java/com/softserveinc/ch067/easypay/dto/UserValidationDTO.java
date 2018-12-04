package com.softserveinc.ch067.easypay.dto;

import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.Role;
import com.softserveinc.ch067.easypay.model.UserStatus;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import java.time.LocalDate;
import java.util.Set;

public class UserValidationDTO {

    private Long id;

    @NotEmpty(message = "Name must contain at least 2 characters!")
    @Pattern(regexp = "^[A-Z][a-z]{1,30}([\\-][A-Z][a-z]{1,30}|)$", message = "Name can contain only latin letters and - sign!")
    private String name;

    @NotEmpty(message = "Surname must contain at least 2 characters!")
    @Pattern(regexp = "^[A-Z][a-z]{1,30}([\\-][A-Z][a-z]{1,30}|)$", message = "Surname can contain only latin letters and - sign!")
    private String surname;

    private String avatar;

    @NotEmpty(message = "Email field is required!")
    @Email(message = "Enter correct email address!")
    @Column(unique = true)
    private String email;

    @NotEmpty(message = "Password must contain at least 7 characters!")
    private String password;

    private Role role;

    private Set<Address> addresses;

    private LocalDate lastLogin;

    @NotEmpty(message = "Phone number is required!")
    @Pattern(regexp = "^\\+(\\d{12})$", message = "Enter valid phone number!")
    private String phoneNumber;

    private UserStatus userStatus;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
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

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public Set<Address> getAddresses() {
        return addresses;
    }

    public void setAddresses(Set<Address> addresses) {
        this.addresses = addresses;
    }

    public LocalDate getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDate lastLogin) {
        this.lastLogin = lastLogin;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public UserStatus getUserStatus() {
        return userStatus;
    }

    public void setUserStatus(UserStatus userStatus) {
        this.userStatus = userStatus;
    }
}
