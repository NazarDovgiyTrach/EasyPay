package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.City;
import com.softserveinc.ch067.easypay.model.Region;
import com.softserveinc.ch067.easypay.model.Street;

import java.util.Map;
import java.util.Set;

public interface ICityService {
    Set<City> getAll();

    City getById(Long id);

    Set<Street> getAllStreets(Long id);

    void create(City city);

    boolean cityUniqueness(String name);

    Map<String, String> getMessages(City city);

    City getByName(String name);

    void update(City city);

}
