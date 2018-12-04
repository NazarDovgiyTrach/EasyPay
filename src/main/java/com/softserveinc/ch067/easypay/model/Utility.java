package com.softserveinc.ch067.easypay.model;

import org.apache.catalina.Manager;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "utilities")
public class Utility {

    @Id
    @SequenceGenerator(name = "utility_sequence", sequenceName = "utility_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "utility_sequence")
    @Column(name = "id")
    private Long id;

    @Pattern(regexp = "(^([A-Z]+[a-z]*\\s*)+\\\"*([A-Za-z]+\\s*.*)+\\\"*\\s*$)|(^([А-ЯІЄЇ]+[а-яієї]*\\s*)+\\\"*([А-ЯІЄЇа-яієї]+\\s*.*)+\\\"*\\s*$)", message = "{utility.name.error}")
    @Column(length = 50)
    private String name;

    @Column(name = "is_active")
    private Boolean active;

    @NotNull(message = "{utility.address.error}")
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id")
    private Address address;

    @Pattern(regexp = "^\\d{6,}$", message = "{utility.identificationCode.error}")
    @Size(min = 6, message = "{utility.identificationCode.error.size}")
    @Column(name = "identification_code")
    private String identificationCode;

    @NotNull(message = "{utility.manager.error}")
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User manager;

    @LazyCollection(LazyCollectionOption.TRUE)
    @OneToMany
    @JoinTable(
            name = "utilities_counters",
            joinColumns = {@JoinColumn(name = "utility_id")},
            inverseJoinColumns = {@JoinColumn(name = "counter_id"),
            }
    )
    private Set<Counter> counters;

    @LazyCollection(LazyCollectionOption.TRUE)
    @OneToMany
    @JoinTable(
            name = "utilities_users",
            joinColumns = {@JoinColumn(name = "utility_id")},
            inverseJoinColumns = {@JoinColumn(name = "user_id")}
    )
    private List<User> inspectors;

    @Column(name = "logo")
    private String logo;

    @Column(name = "phone")
    private String phoneNumber;

    @Column(name = "web_site")
    private String webSite;

    public Utility() {
    }

    public Utility(Long id) {
        this.id = id;
    }

    public Utility(Long id, Address address, User manager, List<User> inspectors, Set<Counter> counters) {
        this.id = id;
        this.address = address;
        this.manager = manager;
        this.inspectors = inspectors;
        this.counters = counters;
    }

    public String getWebSite() {
        return webSite;
    }

    public void setWebSite(String webSite) {
        this.webSite = webSite;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
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

    public Boolean getActive() {
        return active;
    }

    public void setActive(Boolean active) {
        this.active = active;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public String getIdentificationCode() {
        return identificationCode;
    }

    public void setIdentificationCode(String identificationCode) {
        this.identificationCode = identificationCode;
    }

    public User getManager() {
        return manager;
    }

    public void setManager(User manager) {
        this.manager = manager;
    }


    public Set<Counter> getCounters() {
        return counters;
    }

    public void setCounters(Set<Counter> counters) {
        this.counters = counters;
    }

    public List<User> getInspectors() {
        return inspectors;
    }

    public void setInspectors(List<User> inspectors) {
        this.inspectors = inspectors;
    }

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
    }

    @Override
    public String toString() {
        return "Utility{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", active=" + active +
                ", address=" + address +
                ", identificationCode='" + identificationCode + '\'' +
                ", manager=" + manager +
                ", logo='" + logo + '\'' +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", webSite='" + webSite + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Utility utility = (Utility) o;
        return Objects.equals(id, utility.id) &&
                Objects.equals(name, utility.name) &&
                Objects.equals(active, utility.active) &&
                Objects.equals(address, utility.address) &&
                Objects.equals(identificationCode, utility.identificationCode) &&
                Objects.equals(manager, utility.manager) &&
                Objects.equals(logo, utility.logo) &&
                Objects.equals(phoneNumber, utility.phoneNumber) &&
                Objects.equals(webSite, utility.webSite);
    }

    @Override
    public int hashCode() {

        return Objects.hash(id, name, active, address, identificationCode, manager, logo, phoneNumber, webSite);
    }
}
