package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.NotNull;
import java.time.LocalDate;
import java.util.Map;

public class PriceHistoryDTO {

    @NotNull(message = "{price.history.error.datesNotNull}")
    private Map<LocalDate, Double> prices;

    public Map<LocalDate, Double> getPrices() {
        return prices;
    }

    public void setPrices(Map<LocalDate, Double> prices) {
        this.prices = prices;
    }
}
