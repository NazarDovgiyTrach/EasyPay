package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

public class PriceAddressDTO {

    @Positive
    private Long addressId;

    @NotNull
    private String cityName;

    @NotNull
    private String streetName;

    @NotNull
    private String houseNumber;

    public Long getAddressId() {
        return addressId;
    }

    public void setAddressId(Long addressId) {
        this.addressId = addressId;
    }

    public String getCityName() {
        return cityName;
    }

    public void setCityName(String cityName) {
        this.cityName = cityName;
    }

    public String getStreetName() {
        return streetName;
    }

    public void setStreetName(String streetName) {
        this.streetName = streetName;
    }

    public String getHouseNumber() {
        return houseNumber;
    }

    public void setHouseNumber(String houseNumber) {
        this.houseNumber = houseNumber;
    }

    @Override
    public String toString() {
        return "PriceAddressDTO{" +
                "addressId=" + addressId +
                ", cityName='" + cityName + '\'' +
                ", streetName='" + streetName + '\'' +
                ", houseNumber='" + houseNumber + '\'' +
                '}';
    }

}
