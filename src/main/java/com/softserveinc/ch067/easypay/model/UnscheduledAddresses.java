package com.softserveinc.ch067.easypay.model;

import javax.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "unscheduled_addresses")
@NamedQueries({
        @NamedQuery(
                name = "UnscheduledAddresses.getByUtilityId",
                query = "SELECT u FROM UnscheduledAddresses u " +
                        "WHERE u.utility.id = :utilityId " +
                        "ORDER BY u.address.region.name ASC, u.address.street.name ASC"
        ),
        @NamedQuery(
                name = "UnscheduledAddresses.getAddressByUtilityId",
                query = "SELECT u.address FROM UnscheduledAddresses u " +
                        "WHERE u.utility.id = :utilityId " +
                        "ORDER BY u.address.region.name ASC, u.address.street.name ASC"
        ),
        @NamedQuery(
                name = "UnscheduledAddresses.getPageSize",
                query = "SELECT COUNT(u) FROM UnscheduledAddresses u " +
                        "WHERE u.utility.id = :utilityId "
        )
})
public class UnscheduledAddresses {
    @Id
    @SequenceGenerator(name = "unscheduled_addresses_sequence", sequenceName = "unscheduled_addresses_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "unscheduled_addresses_sequence")
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id", nullable = false)
    private Address address;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "utility_id", nullable = false)
    private Utility utility;

    public UnscheduledAddresses() {
    }

    public UnscheduledAddresses(Address address, Utility utility) {
        this.address = address;
        this.utility = utility;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public Utility getUtility() {
        return utility;
    }

    public void setUtility(Utility utility) {
        this.utility = utility;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UnscheduledAddresses that = (UnscheduledAddresses) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(address, that.address) &&
                Objects.equals(utility, that.utility);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, address, utility);
    }

    @Override
    public String toString() {
        return "UnscheduledAddresses{" +
                "id=" + id +
                ", address=" + address +
                ", utility=" + utility +
                '}';
    }
}
