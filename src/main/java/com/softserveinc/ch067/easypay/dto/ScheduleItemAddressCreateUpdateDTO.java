package com.softserveinc.ch067.easypay.dto;

import io.swagger.annotations.ApiModelProperty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

public class ScheduleItemAddressCreateUpdateDTO {

    @ApiModelProperty(position = 1, notes = "ID address in Data Base", required = true, dataType = "Long", example = "123")
    @NotNull(message = "{schedule.address.id.error.null}")
    @Positive(message = "{schedule.address.id.error.positive}")
    private Long id;

    public ScheduleItemAddressCreateUpdateDTO() {
    }

    public ScheduleItemAddressCreateUpdateDTO(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "ScheduleItemAddressCreateUpdateDTO{" +
                "id=" + id +
                '}';
    }
}
