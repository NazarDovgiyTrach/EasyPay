package com.softserveinc.ch067.easypay.model;

import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import javax.validation.constraints.Pattern;
import java.util.Set;

@Entity
public class Region {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "region_sequence")
    @SequenceGenerator(name = "region_sequence", sequenceName = "region_sequence_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;


    //@Pattern(regexp = "[A-ZА-ЯІЇЄ][a-zа-яіїє]{1,30}([\\-\\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String name;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "region")
    private Set<City> cities;

    public Region() {
    }

    public Region(String name, Set<City> cities) {
        this.name = name;
        this.cities = cities;
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

    public Set<City> getCities() {
        return cities;
    }

    public void setCities(Set<City> cities) {
        this.cities = cities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Region region = (Region) o;

        if (id != null ? !id.equals(region.id) : region.id != null) return false;
        return name != null ? name.equals(region.name) : region.name == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Region{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
