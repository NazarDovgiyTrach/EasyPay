package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import javax.validation.constraints.Pattern;
import java.util.Set;

@Entity
public class Street {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "city_sequence")
    @SequenceGenerator(name = "city_sequence", sequenceName = "city_sequence_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;


    //@Pattern(regexp = "[a-zа-яіїє]{1,30}([\\-\\s][A-ZА-ЯІЇЄa-zа-я][a-zа-яіїє]{1,30}|)", message = "Invalid name! Must begin with capital letter and contain at least one small letter!")
    private String name;

    @ManyToOne
    @JoinColumn(name = "city_id")
    @JsonIgnore
    private City city;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "street")
    private Set<House> houses;

    public Street() {
    }

    public Street(String name, City city, Set<House> houses) {
        this.name = name;
        this.city = city;
        this.houses = houses;
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

    public Set<House> getHouses() {
        return houses;
    }

    public void setHouses(Set<House> houses) {
        this.houses = houses;
    }

    public City getCity() {
        return city;
    }

    public void setCity(City city) {
        this.city = city;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Street street = (Street) o;

        if (id != null ? !id.equals(street.id) : street.id != null) return false;
        if (name != null ? !name.equals(street.name) : street.name != null) return false;
        return city != null ? city.equals(street.city) : street.city == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + (city != null ? city.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Street{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", city=" + city.getName() +
                '}';
    }
}
