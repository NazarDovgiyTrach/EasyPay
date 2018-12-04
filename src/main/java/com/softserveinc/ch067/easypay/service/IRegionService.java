package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.City;
import com.softserveinc.ch067.easypay.model.Region;

import java.util.Set;

public interface IRegionService {
    Set<Region> getAllRegionNames();

    Region getById(Long id);

    Set<City> getAllCities(Long id);

    void create(Region region);

    boolean regionUniqueness(String name);

    Region getByName(String name);

    void update(Region region);
}
