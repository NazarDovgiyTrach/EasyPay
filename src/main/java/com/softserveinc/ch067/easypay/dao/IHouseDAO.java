package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.House;

import java.util.Set;

public interface IHouseDAO extends IModel<House> {
    Set<House> getAllNumbers();

    boolean isUniqueness(String number, Long streetId);

    House getByNumberAndStreetId(String number, Long streetId);
}
