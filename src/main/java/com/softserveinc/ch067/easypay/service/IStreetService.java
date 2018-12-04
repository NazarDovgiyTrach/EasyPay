package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.House;
import com.softserveinc.ch067.easypay.model.Street;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface IStreetService {
    Set<Street> getAll();

    Street getById(Long id);

    Set<House> getAllHouses(Long id);

    void create(Street street);

    boolean isUniqueness(String name, Long cityId);

    Map<String, String> getMessages(Street street);

    Street getByNameAndCityId(String name, Long cityId);

    void update(Street street);

    List<Street> getStreetsByAuthInspectorId(Long id);
}
