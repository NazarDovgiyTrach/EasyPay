package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import javax.persistence.*;

@Entity
@Table(name = "addresses")
public class Address {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "address_sequence")
    @SequenceGenerator(name = "address_sequence", sequenceName = "address_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;
    @OneToOne
    private Region region;
    @OneToOne
    private City city;
    @OneToOne
    private Street street;
    @OneToOne
    private House house;
    @OneToOne
    private Flat flat;

    private double lat;

    private double lng;

    @Column(name = "is_active")
    private boolean isActive;

    public Address() {
    }

    public Address(Region region, City city, Street street, House house, Flat flat, double lat, double lng, boolean isActive) {
        this.region = region;
        this.city = city;
        this.street = street;
        this.house = house;
        this.flat = flat;
        this.lat = lat;
        this.lng = lng;
        this.isActive = isActive;
    }



    public Address(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Region getRegion() {
        return region;
    }

    public void setRegion(Region region) {
        this.region = region;
    }

    public City getCity() {
        return city;
    }

    public void setCity(City city) {
        this.city = city;
    }

    public Street getStreet() {
        return street;
    }

    public void setStreet(Street street) {
        this.street = street;
    }

    public House getHouse() {
        return house;
    }

    public void setHouse(House house) {
        this.house = house;
    }

    public Flat getFlat() {
        return flat;
    }

    public void setFlat(Flat flat) {
        this.flat = flat;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
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

    public String getFullAddressString(){
//        return this.region.getName() + " region, " + this.city.getName() + " city, " + this.street.getName() + " street, " + this.house.getNumber() + "/" + this.flat.getNumber();
   return  null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Address address = (Address) o;

        if (Double.compare(address.lat, lat) != 0) return false;
        if (Double.compare(address.lng, lng) != 0) return false;
        if (isActive != address.isActive) return false;
        if (id != null ? !id.equals(address.id) : address.id != null) return false;
        if (region != null ? !region.equals(address.region) : address.region != null) return false;
        if (city != null ? !city.equals(address.city) : address.city != null) return false;
        if (street != null ? !street.equals(address.street) : address.street != null) return false;
        if (house != null ? !house.equals(address.house) : address.house != null) return false;
        return flat != null ? flat.equals(address.flat) : address.flat == null;
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
        result = 31 * result + (isActive ? 1 : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Address{" +
                "id=" + id +
                ", region=" + region +
                ", city=" + city +
                ", street=" + street +
                ", house=" + house +
                ", flat=" + flat +
                ", lat=" + lat +
                ", lng=" + lng +
                ", isActive=" + isActive +
                '}';
    }
}
