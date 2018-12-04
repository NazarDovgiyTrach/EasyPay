package com.softserveinc.ch067.easypay.model;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.time.LocalDate;
import java.util.Objects;

@Entity
@Table(name = "prices")
public class CurrentPrice {

    @Id
    @SequenceGenerator(name = "price_sequence", sequenceName = "price_sequence_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "price_sequence")
    @Column(name = "price_id")
    private Long currentPriceId;

    @Column(precision = 10, scale = 2)
    @Positive(message = "{manager.price.error.positive}")
    @Digits(integer = 10, fraction = 2, message = "{manager.price.error.toManyDigits}")
    private double price;

    @ManyToOne
    @JoinColumn(name = "utility_id")
    private Utility utility;

    @Column(name = "date")
    @PastOrPresent(message = "{manager.price.error.FutureOrPresent}")
    private LocalDate date;

    @Column(name = "active")
    private boolean active;

    public CurrentPrice() {
    }

    public Long getCurrentPriceId() {
        return currentPriceId;
    }

    public void setCurrentPriceId(Long currentPriceId) {
        this.currentPriceId = currentPriceId;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public Utility getUtility() {
        return utility;
    }

    public void setUtility(Utility utility) {
        this.utility = utility;
    }

    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate date) {
        this.date = date;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public String toString() {
        return "CurrentPrice{" +
                "currentPriceId=" + currentPriceId +
                ", price=" + price +
                ", utility=" + utility +
                ", date=" + date +
                ", active=" + active +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CurrentPrice)) return false;
        CurrentPrice that = (CurrentPrice) o;
        return Double.compare(that.getPrice(), getPrice()) == 0 &&
                isActive() == that.isActive() &&
                Objects.equals(getCurrentPriceId(), that.getCurrentPriceId()) &&
                Objects.equals(getUtility(), that.getUtility()) &&
                Objects.equals(getDate(), that.getDate());
    }

    @Override
    public int hashCode() {

        return Objects.hash(getCurrentPriceId(), getPrice(), getUtility(), getDate(), isActive());
    }
}
