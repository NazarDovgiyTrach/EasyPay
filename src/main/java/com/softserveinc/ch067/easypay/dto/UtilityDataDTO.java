package com.softserveinc.ch067.easypay.dto;

import java.util.Objects;

public class UtilityDataDTO {

    private Long id;

    private String name;

    private Boolean active;

    private UtilityAddressDTO address;

    private String identificationCode;

    private UserDataDTO manager;

    private String logo;

    private String phoneNumber;

    private String webSite;

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

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public UtilityAddressDTO getAddress() {
        return address;
    }

    public void setAddress(UtilityAddressDTO address) {
        this.address = address;
    }

    public String getIdentificationCode() {
        return identificationCode;
    }

    public void setIdentificationCode(String identificationCode) {
        this.identificationCode = identificationCode;
    }

    public UserDataDTO getManager() {
        return manager;
    }

    public void setManager(UserDataDTO manager) {
        this.manager = manager;
    }

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getWebSite() {
        return webSite;
    }

    public void setWebSite(String webSite) {
        this.webSite = webSite;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UtilityDataDTO that = (UtilityDataDTO) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(name, that.name) &&
                Objects.equals(active, that.active) &&
                Objects.equals(address, that.address) &&
                Objects.equals(identificationCode, that.identificationCode) &&
                Objects.equals(manager, that.manager) &&
                Objects.equals(logo, that.logo) &&
                Objects.equals(phoneNumber, that.phoneNumber) &&
                Objects.equals(webSite, that.webSite);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, name, active, address, identificationCode, manager, logo, phoneNumber, webSite);
    }

    @Override
    public String toString() {
        return "UtilityDataDTO{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", active=" + active +
                ", address=" + address +
                ", identificationCode='" + identificationCode + '\'' +
                ", manager=" + manager +
                ", logo='" + logo + '\'' +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", webSite='" + webSite + '\'' +
                '}';
    }
}
