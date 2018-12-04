package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.Street;

import java.util.Set;

public interface IStreetDAO extends IModel<Street> {
    Set<Street> getAllNames();

    boolean isUniqueness(String name, Long cityId);

    Street getByNameAndCityId(String nam, Long cityId);
}
