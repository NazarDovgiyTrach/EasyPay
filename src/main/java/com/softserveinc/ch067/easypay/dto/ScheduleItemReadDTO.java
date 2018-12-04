package com.softserveinc.ch067.easypay.dto;

import java.time.LocalDate;

public class ScheduleItemReadDTO {
    private Long id;
    private ScheduleItemAddressReadDTO address;
    private LocalDate eventDate;
    private Boolean isRepeat;

    public ScheduleItemReadDTO() {
    }

    public ScheduleItemReadDTO(Long id, ScheduleItemAddressReadDTO address, LocalDate eventDate, Boolean isRepeat) {
        this.id = id;
        this.address = address;
        this.eventDate = eventDate;
        this.isRepeat = isRepeat;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ScheduleItemAddressReadDTO getAddress() {
        return address;
    }

    public void setAddress(ScheduleItemAddressReadDTO address) {
        this.address = address;
    }

    public LocalDate getEventDate() {
        return eventDate;
    }

    public void setEventDate(LocalDate eventDate) {
        this.eventDate = eventDate;
    }

    public Boolean getRepeat() {
        return isRepeat;
    }

    public void setRepeat(Boolean repeat) {
        isRepeat = repeat;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ScheduleItemReadDTO that = (ScheduleItemReadDTO) o;

        if (id != null ? !id.equals(that.id) : that.id != null) return false;
        if (address != null ? !address.equals(that.address) : that.address != null) return false;
        if (eventDate != null ? !eventDate.equals(that.eventDate) : that.eventDate != null) return false;
        return isRepeat != null ? isRepeat.equals(that.isRepeat) : that.isRepeat == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (eventDate != null ? eventDate.hashCode() : 0);
        result = 31 * result + (isRepeat != null ? isRepeat.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ScheduleItemReadDTO{" +
                "id=" + id +
                ", address=" + address +
                ", eventDate=" + eventDate +
                ", isRepeat=" + isRepeat +
                '}';
    }
}
