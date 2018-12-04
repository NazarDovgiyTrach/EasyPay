package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

public class UtilityPriceDTO {
    @Positive
    private Long utilityId;

    @NotNull
    private String utilityName;

    private boolean active;

    public Long getUtilityId() {
        return utilityId;
    }

    public void setUtilityId(Long utilityId) {
        this.utilityId = utilityId;
    }

    public String getUtilityName() {
        return utilityName;
    }

    public void setUtilityName(String utilityName) {
        this.utilityName = utilityName;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    @Override
    public String toString() {
        return "UtilityPriceDTO{" +
                "utilityId=" + utilityId +
                ", utilityName='" + utilityName + '\'' +
                ", active=" + active +
                '}';
    }
}
