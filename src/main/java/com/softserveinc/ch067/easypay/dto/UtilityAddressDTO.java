package com.softserveinc.ch067.easypay.dto;

import java.util.Objects;

public class UtilityAddressDTO {
    private Long id;
    private String regionName;
    private String cityName;
    private String streetName;
    private String houseNumber;
    private String flatNumber;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRegionName() {
        return regionName;
    }

    public void setRegionName(String regionName) {
        this.regionName = regionName;
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

    public String getFlatNumber() {
        return flatNumber;
    }

    public void setFlatNumber(String flatNumber) {
        this.flatNumber = flatNumber;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UtilityAddressDTO that = (UtilityAddressDTO) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(regionName, that.regionName) &&
                Objects.equals(cityName, that.cityName) &&
                Objects.equals(streetName, that.streetName) &&
                Objects.equals(houseNumber, that.houseNumber) &&
                Objects.equals(flatNumber, that.flatNumber);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, regionName, cityName, streetName, houseNumber, flatNumber);
    }

    @Override
    public String toString() {
        return "UtilityAddressDTO{" +
                "id=" + id +
                ", regionName='" + regionName + '\'' +
                ", cityName='" + cityName + '\'' +
                ", streetName='" + streetName + '\'' +
                ", houseNumber='" + houseNumber + '\'' +
                ", flatNumber='" + flatNumber + '\'' +
                '}';
    }
}
