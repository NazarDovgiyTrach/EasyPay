package com.softserveinc.ch067.easypay.dto;

import com.softserveinc.ch067.easypay.model.Counter;

import java.util.List;

public class UtilityCountersDTO {

    private String utilityName;
    private List<Counter> counters;

    public String getUtilityName() {
        return utilityName;
    }

    public void setUtilityName(String utilityName) {
        this.utilityName = utilityName;
    }

    public List<Counter> getCounters() {
        return counters;
    }

    public void setCounters(List<Counter> counters) {
        this.counters = counters;
    }
}
