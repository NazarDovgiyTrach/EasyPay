package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.Region;

import java.util.List;
import java.util.Set;

public interface IRegionDAO extends IModel<Region> {
    Set<Region> getAllNames();

    Region getById(Long id);

    boolean regionUniqueness(String name);

    Region getByName(String name);
}
