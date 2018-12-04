package com.softserveinc.ch067.easypay.dto;

public class ScheduleItemAddressReadDTO {
    private Long id;
    private ScheduleItemRegionDTO region;
    private ScheduleItemCityDTO city;
    private ScheduleItemStreetDTO street;
    private ScheduleItemHouseDTO house;
    private ScheduleItemFlatDTO flat;
    private double lat;
    private double lng;

    public ScheduleItemAddressReadDTO() {
    }

    public ScheduleItemAddressReadDTO(Long id,
                                      ScheduleItemRegionDTO region,
                                      ScheduleItemCityDTO city,
                                      ScheduleItemStreetDTO street,
                                      ScheduleItemHouseDTO house,
                                      ScheduleItemFlatDTO flat,
                                      double lat,
                                      double lng) {
        this.id = id;
        this.region = region;
        this.city = city;
        this.street = street;
        this.house = house;
        this.flat = flat;
        this.lat = lat;
        this.lng = lng;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ScheduleItemRegionDTO getRegion() {
        return region;
    }

    public void setRegion(ScheduleItemRegionDTO region) {
        this.region = region;
    }

    public ScheduleItemCityDTO getCity() {
        return city;
    }

    public void setCity(ScheduleItemCityDTO city) {
        this.city = city;
    }

    public ScheduleItemStreetDTO getStreet() {
        return street;
    }

    public void setStreet(ScheduleItemStreetDTO street) {
        this.street = street;
    }

    public ScheduleItemHouseDTO getHouse() {
        return house;
    }

    public void setHouse(ScheduleItemHouseDTO house) {
        this.house = house;
    }

    public ScheduleItemFlatDTO getFlat() {
        return flat;
    }

    public void setFlat(ScheduleItemFlatDTO flat) {
        this.flat = flat;
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ScheduleItemAddressReadDTO that = (ScheduleItemAddressReadDTO) o;

        if (Double.compare(that.lat, lat) != 0) return false;
        if (Double.compare(that.lng, lng) != 0) return false;
        if (id != null ? !id.equals(that.id) : that.id != null) return false;
        if (region != null ? !region.equals(that.region) : that.region != null) return false;
        if (city != null ? !city.equals(that.city) : that.city != null) return false;
        if (street != null ? !street.equals(that.street) : that.street != null) return false;
        if (house != null ? !house.equals(that.house) : that.house != null) return false;
        return flat != null ? flat.equals(that.flat) : that.flat == null;
    }

    @Override
    public int hashCode() {
        int result;
        long temp;
        result = id != null ? id.hashCode() : 0;
        result = 31 * result + (region != null ? region.hashCode() : 0);
        result = 31 * result + (city != null ? city.hashCode() : 0);
        result = 31 * result + (street != null ? street.hashCode() : 0);
        result = 31 * result + (house != null ? house.hashCode() : 0);
        result = 31 * result + (flat != null ? flat.hashCode() : 0);
        temp = Double.doubleToLongBits(lat);
        result = 31 * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(lng);
        result = 31 * result + (int) (temp ^ (temp >>> 32));
        return result;
    }

    @Override
    public String toString() {
        return "ScheduleItemAddressReadDTO{" +
                "id=" + id +
                ", region=" + region +
                ", city=" + city +
                ", street=" + street +
                ", house=" + house +
                ", flat=" + flat +
                ", lat=" + lat +
                ", lng=" + lng +
                '}';
    }
}

class ScheduleItemRegionDTO {
    private String name;

    public ScheduleItemRegionDTO() {
    }

    public ScheduleItemRegionDTO(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "ScheduleItemRegionDTO{" +
                "name='" + name + '\'' +
                '}';
    }
}

class ScheduleItemCityDTO {
    private String name;

    public ScheduleItemCityDTO() {
    }

    public ScheduleItemCityDTO(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "ScheduleItemCityDTO{" +
                "name='" + name + '\'' +
                '}';
    }
}

class ScheduleItemStreetDTO {
    private String name;

    public ScheduleItemStreetDTO() {
    }

    public ScheduleItemStreetDTO(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "ScheduleItemStreetDTO{" +
                "name='" + name + '\'' +
                '}';
    }
}

class ScheduleItemHouseDTO {
    private String number;

    public ScheduleItemHouseDTO() {
    }

    public ScheduleItemHouseDTO(String number) {
        this.number = number;
    }

    public String getNumber() {
        return number;
    }

    public void setNumber(String number) {
        this.number = number;
    }

    @Override
    public String toString() {
        return "ScheduleItemHouseDTO{" +
                "number='" + number + '\'' +
                '}';
    }
}

class ScheduleItemFlatDTO {
    private String number;

    public ScheduleItemFlatDTO() {
    }

    public ScheduleItemFlatDTO(String number) {
        this.number = number;
    }

    public String getNumber() {
        return number;
    }

    public void setNumber(String number) {
        this.number = number;
    }

    @Override
    public String toString() {
        return "ScheduleItemFlatDTO{" +
                "number='" + number + '\'' +
                '}';
    }
}