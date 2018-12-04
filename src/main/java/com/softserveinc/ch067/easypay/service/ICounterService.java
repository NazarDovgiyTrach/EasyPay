package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.Utility;

import java.time.LocalDate;
import java.util.List;

public interface ICounterService {
    List<Counter> getAll();

    void create(Counter counter);

    List<Counter> getAllByUserId(Long id);

    void update(Counter counter);

    Counter getById(Long id);

    List<Counter> getCountersByAddressIdAndUtility(Long id, Utility utility);

    void updateCounterCurrentValue(Long id, Long newValue);

    void updateCounterStatus(Long id, boolean active);

    void updateCounterType(Long id, boolean fixed);

    void initWithValues(Counter counter);

    List<Counter> getFixedCounterForRegularPay(LocalDate beforeDate, int maxResults);



}
