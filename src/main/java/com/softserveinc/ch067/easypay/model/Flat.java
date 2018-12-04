package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import javax.validation.constraints.Pattern;

@Entity
public class Flat {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "flat_sequence")
    @SequenceGenerator(name = "flat_sequence", sequenceName = "flat_sequence_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "house_id")
    @JsonIgnore
    private House house;


    //@Pattern(regexp = "\\d{1,3}", message = "Invalid number! Must contain max three digit number!")
    private String number;

    public Flat() {
    }

    public Flat(House house, String number) {
        this.house = house;
        this.number = number;
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

    public House getHouse() {
        return house;
    }

    public void setHouse(House house) {
        this.house = house;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Flat flat = (Flat) o;

        if (id != null ? !id.equals(flat.id) : flat.id != null) return false;
        return number != null ? number.equals(flat.number) : flat.number == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (number != null ? number.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Flat{" +
                "id=" + id +
                ", house=" + house.getNumber() +
                ", number='" + number + '\'' +
                '}';
    }
}
