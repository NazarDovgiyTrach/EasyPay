package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.DecimalMax;
import javax.validation.constraints.DecimalMin;
import javax.validation.constraints.NotNull;
import java.math.BigDecimal;

public class RatingDTO {

    @NotNull
    private Long userId;

    @DecimalMin(value = "0.0")
    @DecimalMax(value = "5.0")
    private BigDecimal ratingValue;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public BigDecimal getRatingValue() {
        return ratingValue;
    }

    public void setRatingValue(BigDecimal ratingValue) {
        this.ratingValue = ratingValue;
    }
}
