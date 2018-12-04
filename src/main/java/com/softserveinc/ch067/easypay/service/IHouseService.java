package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Flat;
import com.softserveinc.ch067.easypay.model.House;

import java.util.Map;
import java.util.Set;

public interface IHouseService {
    Set<House> getAll();

    House getById(Long id);

    Set<Flat> getAllFlats(Long id);

    void create(House house);

    boolean isUniqueness(String number, Long streetId);

    Map<String, String> getMessages(House house);

    House getByNumberAndStreetId(String number, Long streetId);

    void update(House house);
}
