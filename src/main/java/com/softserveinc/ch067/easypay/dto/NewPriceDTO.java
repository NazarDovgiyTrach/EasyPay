package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.Digits;
import javax.validation.constraints.Future;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import java.time.LocalDate;

public class NewPriceDTO {

    private Long currentPriceId;
    private Long newPriceId;

    @Positive(message = "{manager.price.error.positive}")
    @Digits(integer = 10, fraction = 2, message = "{manager.price.error.toManyDigits}")
    private double newPrice;

    @NotNull(message = "{manager.price.error.notNullDate}")
    @Future(message = "{manager.price.error.FutureDate}")
    private LocalDate activationDate;

    public Long getNewPriceId() {
        return newPriceId;
    }

    public void setNewPriceId(Long newPriceId) {
        this.newPriceId = newPriceId;
    }

    public double getNewPrice() {
        return newPrice;
    }

    public void setNewPrice(double newPrice) {
        this.newPrice = newPrice;
    }

    public LocalDate getActivationDate() {
        return activationDate;
    }

    public void setActivationDate(LocalDate activationDate) {
        this.activationDate = activationDate;
    }

    public Long getCurrentPriceId() {
        return currentPriceId;
    }

    public void setCurrentPriceId(Long currentPriceId) {
        this.currentPriceId = currentPriceId;
    }

    @Override
    public String toString() {
        return "NewPriceDTO{" +
                "currentPriceId=" + currentPriceId +
                ", newPriceId=" + newPriceId +
                ", newPrice=" + newPrice +
                ", activationDate=" + activationDate +
                '}';
    }

}
