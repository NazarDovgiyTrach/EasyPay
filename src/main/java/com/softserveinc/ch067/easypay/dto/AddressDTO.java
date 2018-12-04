package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.Pattern;

public class AddressDTO {

    @Pattern(regexp = "(([A-Za-zА-ЯІЇЄа-яіїє'-]){1,30})([\\-\\s][A-Za-zА-ЯІЇЄа-яіїє]{1,30})", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String region;
    @Pattern(regexp = "[A-ZА-ЯІЇЄ][a-zа-яіїє]{1,30}([\\-\\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String country;
    @Pattern(regexp = "(^$|\\d{1,3})", message = "Invalid input")
    private String flat;
    @Pattern(regexp = "[A-ZА-ЯІЇЄ][a-zа-яіїє]{1,30}([\\-\\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String locality;
    private String postalCode;
    @Pattern(regexp = "([A-Za-zА-ЯІЇЄа-яіїє]{1,30})([\\-\\s][A-Za-zА-ЯІЇЄа-яіїє]{1,30})", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String route;
    @Pattern(regexp = "\\d{1,3}(|[A-ZА-ЯІЇЄ]{1})", message = "Invalid house number! Must begin with digit, max length three digit number, and contain max one capital letter at the end!")
    private String streetNumber;

    private double lat;
    private double lng;

    public AddressDTO() {
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getFlat() {
        return flat;
    }

    public void setFlat(String flat) {
        this.flat = flat;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getRoute() {
        return route;
    }

    public void setRoute(String route) {
        this.route = route;
    }

    public String getStreetNumber() {
        return streetNumber;
    }

    public void setStreetNumber(String streetNumber) {
        this.streetNumber = streetNumber;
    }

    public double getLat() {
        return lat;
    }

    public void setLat(double lat) {
        this.lat = lat;
    }

    public double getLng() {
        return lng;
    }

    public void setLng(double lng) {
        this.lng = lng;
    }

    @Override
    public String toString() {
        return "AddressDTO{" +
                "region='" + region + '\'' +
                ", country='" + country + '\'' +
                ", flat='" + flat + '\'' +
                ", locality='" + locality + '\'' +
                ", postalCode='" + postalCode + '\'' +
                ", route='" + route + '\'' +
                ", streetNumber='" + streetNumber + '\'' +
                ", lat=" + lat +
                ", lng=" + lng +
                '}';
    }
}
