package com.softserveinc.ch067.easypay.dto;

import java.time.LocalDate;

public class CallDTO {
    private Long utilityId;
    private LocalDate date;

    public Long getUtilityId() {
        return utilityId;
    }

    public void setUtilityId(Long utilityId) {
        this.utilityId = utilityId;
    }

    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate date) {
        this.date = date;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CallDTO callDTO = (CallDTO) o;

        if (utilityId != null ? !utilityId.equals(callDTO.utilityId) : callDTO.utilityId != null) return false;
        return date != null ? date.equals(callDTO.date) : callDTO.date == null;
    }

    @Override
    public int hashCode() {
        int result = utilityId != null ? utilityId.hashCode() : 0;
        result = 31 * result + (date != null ? date.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "CallDTO{" +
                "utilityId=" + utilityId +
                ", date=" + date +
                '}';
    }
}
