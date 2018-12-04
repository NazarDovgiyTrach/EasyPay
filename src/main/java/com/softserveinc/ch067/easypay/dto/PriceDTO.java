package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.Digits;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.PastOrPresent;
import javax.validation.constraints.Positive;
import java.time.LocalDate;

public class PriceDTO {

    private Long currentPriceId;

    @Positive(message = "{manager.price.error.positive}")
    @Digits(integer = 10, fraction = 2, message = "{manager.price.error.toManyDigits}")
    private double price;

    @PastOrPresent(message = "{manager.price.error.FutureOrPresent}")
    private LocalDate date;

    @NotNull
    private UtilityPriceDTO utilityPriceDTO;

    @NotNull
    private PriceAddressDTO priceAddressDTO;

    private boolean active;

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

    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate date) {
        this.date = date;
    }

    public UtilityPriceDTO getUtilityPriceDTO() {
        return utilityPriceDTO;
    }

    public void setUtilityPriceDTO(UtilityPriceDTO utilityPriceDTO) {
        this.utilityPriceDTO = utilityPriceDTO;
    }

    public PriceAddressDTO getPriceAddressDTO() {
        return priceAddressDTO;
    }

    public void setPriceAddressDTO(PriceAddressDTO priceAddressDTO) {
        this.priceAddressDTO = priceAddressDTO;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public String toString() {
        return "PriceDTO{" +
                "currentPriceId=" + currentPriceId +
                ", price=" + price +
                ", date=" + date +
                ", utilityPriceDTO=" + utilityPriceDTO +
                ", priceAddressDTO=" + priceAddressDTO +
                ", active=" + active +
                '}';
    }
}
