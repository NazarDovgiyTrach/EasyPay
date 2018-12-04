package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.Flat;

import java.util.Set;

public interface IFlatDAO extends IModel<Flat> {
    Set<Flat> getAllNumbers();

    boolean isUniqueness(String number, Long houseId);

    Flat getByNumberAndHouseId(String name, Long houseId);
}