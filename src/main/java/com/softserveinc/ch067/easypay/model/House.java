package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import javax.validation.constraints.Pattern;
import java.util.Set;

@Entity
public class House {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "house_sequence")
    @SequenceGenerator(name = "house_sequence", sequenceName = "house_sequence_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;

    //@Pattern(regexp = "\\d{1,3}(|[A-ZА-ЯІЇЄ]{1})", message = "Invalid house number! Must begin with digit, max length three digit number, and contain max one capital letter at the end!")

    private String number;

    @ManyToOne
    @JoinColumn(name = "street_id")
    @JsonIgnore
    private Street street;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "house")
    private Set<Flat> flats;

    public House() {
    }

    public House(String number, Street street, Set<Flat> flats) {
        this.number = number;
        this.street = street;
        this.flats = flats;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNumber() {
        return number;
    }

    public void setNumber(String number) {
        this.number = number;
    }

    public Set<Flat> getFlats() {
        return flats;
    }

    public void setFlats(Set<Flat> flats) {
        this.flats = flats;
    }

    public Street getStreet() {
        return street;
    }

    public void setStreet(Street street) {
        this.street = street;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        House house = (House) o;

        if (id != null ? !id.equals(house.id) : house.id != null) return false;
        if (number != null ? !number.equals(house.number) : house.number != null) return false;
        return street != null ? street.equals(house.street) : house.street == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (number != null ? number.hashCode() : 0);
        result = 31 * result + (street != null ? street.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "House{" +
                "id=" + id +
                ", number='" + number + '\'' +
                ", street=" + street.getName() +
                '}';
    }
}
