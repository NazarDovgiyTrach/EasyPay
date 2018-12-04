package com.softserveinc.ch067.easypay.dto;


import java.time.LocalDate;

public class ReminderInfoDTO {

    private String utilityName;

    private String userName;

    private String userSurname;

    private String userEmail;

    private Long addressId;

    private Long utilityId;

    private String street;

    private String house;

    private String flat;

    private Double debt;

    private String phoneNumber;

    public ReminderInfoDTO() {
    }

    public ReminderInfoDTO(Double debt, String utilityName, Long debtId,
                           String userName, String userSurname, String userEmail, String phoneNumber,
                           String street, String house, String flat) {
        this.debt = debt;
        this.utilityName = utilityName;
        this.userName = userName;
        this.userSurname = userSurname;
        this.userEmail = userEmail;
        this.street = street;
        this.house = house;
        this.flat = flat;
        this.phoneNumber = phoneNumber;
    }


    public Double getDebt() {
        return debt;
    }

    public void setDebt(Double debt) {
        this.debt = debt;
    }

    public String getUtilityName() {
        return utilityName;
    }

    public void setUtilityName(String utilityName) {
        this.utilityName = utilityName;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserSurname() {
        return userSurname;
    }

    public void setUserSurname(String userSurname) {
        this.userSurname = userSurname;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public String getStreet() {
        return street;
    }

    public void setStreet(String street) {
        this.street = street;
    }

    public String getHouse() {
        return house;
    }

    public void setHouse(String house) {
        this.house = house;
    }

    public String getFlat() {
        return flat;
    }

    public void setFlat(String flat) {
        this.flat = flat;
    }

    public Long getAddressId() {
        return addressId;
    }

    public void setAddressId(Long addressId) {
        this.addressId = addressId;
    }

    public Long getUtilityId() {
        return utilityId;
    }

    public void setUtilityId(Long utilityId) {
        this.utilityId = utilityId;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }


}
