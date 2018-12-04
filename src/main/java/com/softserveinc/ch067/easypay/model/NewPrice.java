package com.softserveinc.ch067.easypay.model;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.time.LocalDate;
import java.util.Objects;

@Entity
@Table(name = "new_prices")
public class NewPrice {

    @Id
    @SequenceGenerator(name = "new_price_sequence", sequenceName = "new_price_sequence_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "new_price_sequence")
    @Column(name = "new_price_id")
    private Long newPriceId;

    @OneToOne
    @NotNull(message = "{manager.price.error.emptyCurrentPrice}")
    @JoinColumn(name = "current_price_id")
    private CurrentPrice currentPrice;

    @Column(name = "activation_date")
    @Future(message = "{manager.price.error.FutureDate}")
    @NotNull(message = "{manager.price.error.notNullDate}")
    private LocalDate activationDate;

    @Column(precision = 10, scale = 2, name = "new_price")
    @Positive(message = "{manager.price.error.positive}")
    @Digits(integer = 10, fraction = 2, message = "{manager.price.error.toManyDigits}")
    private double newPrice;

    public NewPrice() {
    }


    public LocalDate getActivationDate() {
        return activationDate;
    }

    public void setActivationDate(LocalDate activationDate) {
        this.activationDate = activationDate;
    }

    public double getNewPrice() {
        return newPrice;
    }

    public void setNewPrice(double newPrice) {
        this.newPrice = newPrice;
    }

    public CurrentPrice getCurrentPrice() {
        return currentPrice;
    }

    public void setCurrentPrice(CurrentPrice currentPrice) {
        this.currentPrice = currentPrice;
    }

    public Long getNewPriceId() {
        return newPriceId;
    }

    public void setNewPriceId(Long newPriceId) {
        this.newPriceId = newPriceId;
    }

    @Override
    public String toString() {
        return "NewPrice{" +
                "newPriceId=" + newPriceId +
                ", currentPrice=" + currentPrice +
                ", activationDate=" + activationDate +
                ", newPrice=" + newPrice +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NewPrice)) return false;
        NewPrice newPrice1 = (NewPrice) o;
        return Double.compare(newPrice1.getNewPrice(), getNewPrice()) == 0 &&
                Objects.equals(getNewPriceId(), newPrice1.getNewPriceId()) &&
                Objects.equals(getCurrentPrice(), newPrice1.getCurrentPrice()) &&
                Objects.equals(getActivationDate(), newPrice1.getActivationDate());
    }

    @Override
    public int hashCode() {

        return Objects.hash(getNewPriceId(), getCurrentPrice(), getActivationDate(), getNewPrice());
    }
}
