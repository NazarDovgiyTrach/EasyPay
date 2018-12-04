package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import javax.validation.constraints.Pattern;
import java.util.Set;

@Entity
public class City {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "city_sequence")
    @SequenceGenerator(name = "city_sequence", sequenceName = "city_sequence_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;


    //@Pattern(regexp = "[A-ZА-ЯІЇЄ][a-zа-яіїє]{1,30}([\\-\\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String name;

    @ManyToOne
    @JoinColumn(name = "region_id")
    @JsonIgnore
    private Region region;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "city")
    private Set<Street> streets;

    public City() {
    }

    public City(String name, Region region, Set<Street> streets) {
        this.name = name;
        this.region = region;
        this.streets = streets;
    }

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

    public Set<Street> getStreets() {
        return streets;
    }

    public void setStreets(Set<Street> streets) {
        this.streets = streets;
    }

    public Region getRegion() {
        return region;
    }

    public void setRegion(Region region) {
        this.region = region;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        City city = (City) o;

        if (id != null ? !id.equals(city.id) : city.id != null) return false;
        if (name != null ? !name.equals(city.name) : city.name != null) return false;
        return region != null ? region.equals(city.region) : city.region == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + (region != null ? region.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "City{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", region=" + region.getName() +
                '}';
    }
}
