package com.softserveinc.ch067.easypay.dto;

import com.softserveinc.ch067.easypay.model.Address;

public class DebtInfoForMailingDTO {


    private String utilityName;

    private String userName;

    private String userSurname;

    private String userEmail;

    private String phoneNumber;

    private Double debt;

    private Long debtId;

    private Address address;

    public DebtInfoForMailingDTO(String utilityName, String userName, String userSurname, String userEmail,
                                 String phoneNumber, Double debt, Long debtId, Address address) {
        this.utilityName = utilityName;
        this.userName = userName;
        this.userSurname = userSurname;
        this.userEmail = userEmail;
        this.phoneNumber = phoneNumber;
        this.debt = debt;
        this.debtId = debtId;
        this.address = address;
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

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public Double getDebt() {
        return debt;
    }

    public void setDebt(Double debt) {
        this.debt = debt;
    }

    public Long getDebtId() {
        return debtId;
    }

    public void setDebtId(Long debtId) {
        this.debtId = debtId;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    @Override
    public String toString() {
        return "DebtInfoForMailingDTO{" +
                "utilityName='" + utilityName + '\'' +
                ", userName='" + userName + '\'' +
                ", userSurname='" + userSurname + '\'' +
                ", userEmail='" + userEmail + '\'' +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", debt=" + debt +
                ", debtId=" + debtId +
                '}';
    }
}
