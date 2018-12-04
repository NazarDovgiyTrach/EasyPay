package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.Objects;

@Entity
@Table(name = "counters")
@NamedQueries({
        @NamedQuery(
                name = "Counter.getAllByUserId",
                query = "SELECT c FROM Counter c WHERE c.user.id = :id"
        ),
        @NamedQuery(
                name = "Counter.getCountersByAddressId",
                query = "SELECT c FROM Counter c WHERE c.address.id = :id"
        ),
        @NamedQuery(
                name = "Counter.getFixedCounterForRegularPay",
                query = "SELECT c FROM Counter c WHERE " +
                        "c.active = true and c.currentValue = 1  and c.fixed = true and" +
                        " (c.lastUpdated is null or c.lastUpdated<:beforeDate)"
        )
})

public class Counter {
    @Id
    @SequenceGenerator(name = "counter_sequence", sequenceName = "counter_sequence_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "counter_sequence")
    @Column(name = "id")
    private Long id;

    @Column(name = "is_active")
    private boolean active;

    @Column(name = "is_fixed")
    private boolean fixed;

    @Column(name = "current_value")
    private Long currentValue;

    @Column(name = "old_value")
    private Long oldValue;

    @Column(name = "last_updated")
    private LocalDate lastUpdated;

    @LazyCollection(LazyCollectionOption.TRUE)
    @ManyToOne
    @JoinColumn(name = "address_id")
    private Address address;

    @LazyCollection(LazyCollectionOption.TRUE)
    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "debt_id")
    private Debt debt;


    public Counter() {
    }

    public Counter(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public boolean isFixed() {
        return fixed;
    }

    public void setFixed(boolean fixed) {
        this.fixed = fixed;
    }

    public Long getCurrentValue() {
        return currentValue;
    }

    public void setCurrentValue(Long currentValue) {
        this.currentValue = currentValue;
    }

    public Long getOldValue() {
        return oldValue;
    }

    public void setOldValue(Long oldValue) {
        this.oldValue = oldValue;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public LocalDate getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(LocalDate lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public Debt getDebt() {
        return debt;
    }

    public void setDebt(Debt debt) {
        this.debt = debt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Counter counter = (Counter) o;

        if (active != counter.active) return false;
        if (fixed != counter.fixed) return false;
        if (id != null ? !id.equals(counter.id) : counter.id != null) return false;
        if (currentValue != null ? !currentValue.equals(counter.currentValue) : counter.currentValue != null)
            return false;
        if (oldValue != null ? !oldValue.equals(counter.oldValue) : counter.oldValue != null) return false;
        if (lastUpdated != null ? !lastUpdated.equals(counter.lastUpdated) : counter.lastUpdated != null) return false;
        if (address != null ? !address.equals(counter.address) : counter.address != null) return false;
        return user != null ? user.equals(counter.user) : counter.user == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (active ? 1 : 0);
        result = 31 * result + (fixed ? 1 : 0);
        result = 31 * result + (currentValue != null ? currentValue.hashCode() : 0);
        result = 31 * result + (oldValue != null ? oldValue.hashCode() : 0);
        result = 31 * result + (lastUpdated != null ? lastUpdated.hashCode() : 0);
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (user != null ? user.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Counter{" +
                "id=" + id +
                ", active=" + active +
                ", fixed=" + fixed +
                ", currentValue=" + currentValue +
                ", oldValue=" + oldValue +
                ", lastUpdated=" + lastUpdated +
                ", address=" + address +
                ", user=" + user +
                '}';
    }
}
