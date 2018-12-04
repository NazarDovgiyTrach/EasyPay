package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Flat;


import java.util.Map;
import java.util.Set;

public interface IFlatService {
    Set<Flat> getAll();

    Flat getById(Long id);

    void create(Flat flat);

    boolean isUniqueness(String number, Long houseId);

    Map<String, String> getMessages(Flat flat);

    Flat getByNumberAndHouseId(String name, Long houseId);

    void update(Flat flat);
}
