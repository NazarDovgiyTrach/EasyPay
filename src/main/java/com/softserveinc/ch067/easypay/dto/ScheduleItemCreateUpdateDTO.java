package com.softserveinc.ch067.easypay.dto;

import io.swagger.annotations.ApiModelProperty;

import javax.validation.Valid;
import javax.validation.constraints.FutureOrPresent;
import javax.validation.constraints.NotNull;
import java.time.LocalDate;

public class ScheduleItemCreateUpdateDTO {

    @ApiModelProperty(position = 1, notes = "Id of address to which this schedule item applies", required = true, dataType = "ScheduleItemAddressCreateUpdateDTO")
    @NotNull(message = "{schedule.id.error.null}")
    @Valid
    private ScheduleItemAddressCreateUpdateDTO address;

    @ApiModelProperty(position = 2, notes = "The deadline for execution of the schedule item", required = true, dataType = "LocalDate", example = "2018-09-31")
    @NotNull(message = "{schedule.eventDate.error.null}")
    @FutureOrPresent(message = "{schedule.eventDate.error.FutureOrPresent}")
    private LocalDate eventDate;

    @ApiModelProperty(position = 3, notes = "Is monthly item of schedule", required = true, dataType = "Boolean", example = "false")
    @NotNull(message = "{schedule.repeat.error.null}")
    private Boolean isRepeat;

    public ScheduleItemCreateUpdateDTO() {
    }

    public ScheduleItemCreateUpdateDTO(ScheduleItemAddressCreateUpdateDTO address, LocalDate eventDate, Boolean isRepeat) {
        this.address = address;
        this.eventDate = eventDate;
        this.isRepeat = isRepeat;
    }

    public ScheduleItemAddressCreateUpdateDTO getAddress() {
        return address;
    }

    public void setAddress(ScheduleItemAddressCreateUpdateDTO address) {
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
    public String toString() {
        return "ScheduleItemCreateUpdateDTO{" +
                "address=" + address +
                ", eventDate=" + eventDate +
                ", isRepeat=" + isRepeat +
                '}';
    }
}
