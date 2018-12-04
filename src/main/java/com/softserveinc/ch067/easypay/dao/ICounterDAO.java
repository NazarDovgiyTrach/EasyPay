package com.softserveinc.ch067.easypay.dao;


import com.softserveinc.ch067.easypay.model.Counter;

import java.time.LocalDate;
import java.util.List;

public interface ICounterDAO extends IModel<Counter> {

    List<Counter> getAllByUserId(Long id);

    List<Counter> getCountersByAddressId(Long id);

    List<Counter> getFixedCounterForRegularPay(LocalDate beforeDate, int maxResults);
}
