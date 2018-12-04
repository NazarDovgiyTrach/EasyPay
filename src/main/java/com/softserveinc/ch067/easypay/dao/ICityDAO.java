package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.City;

import java.util.HashSet;
import java.util.Set;

public interface ICityDAO extends IModel<City> {
    Set<City> getAllNames();

    boolean cityUniqueness(String name);

    City getByName(String name);
}
