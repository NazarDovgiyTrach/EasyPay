package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IRegionDAO;
import com.softserveinc.ch067.easypay.model.City;
import com.softserveinc.ch067.easypay.model.Region;
import com.softserveinc.ch067.easypay.service.IRegionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
public class RegionServiceImpl implements IRegionService {
    private final IRegionDAO regionDAO;

    @Autowired
    public RegionServiceImpl(IRegionDAO regionDAO) {
        this.regionDAO = regionDAO;
    }

    @Override
    public Set<Region> getAllRegionNames() {
        return regionDAO.getAllNames();
    }

    @Override
    public Region getById(Long id) {
        return regionDAO.getById(id);
    }

    @Override
    public Set<City> getAllCities(Long id) {
        return regionDAO.getById(id).getCities();
    }

    @Override
    @Transactional
    public void create(Region region) {
        regionDAO.create(region);
    }

    @Override
    public boolean regionUniqueness(String name) {
        return regionDAO.regionUniqueness(name);
    }

    @Override
    public Region getByName(String name) {
        return regionDAO.getByName(name);
    }

    @Transactional
    @Override
    public void update(Region region) {
        regionDAO.update(region);
    }
}
