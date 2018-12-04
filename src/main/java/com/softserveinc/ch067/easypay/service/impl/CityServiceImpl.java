package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.ICityDAO;
import com.softserveinc.ch067.easypay.model.City;
import com.softserveinc.ch067.easypay.model.Street;
import com.softserveinc.ch067.easypay.service.ICityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class CityServiceImpl implements ICityService {
    private final ICityDAO cityDAO;

    @Autowired
    public CityServiceImpl(ICityDAO cityDAO) {
        this.cityDAO = cityDAO;
    }

    @Override
    public Set<City> getAll() {
        return cityDAO.getAllNames();
    }

    @Override
    public City getById(Long id) {
        return cityDAO.getById(id);
    }

    @Override
    public Set<Street> getAllStreets(Long id) {
        return cityDAO.getById(id).getStreets();
    }

    @Override
    @Transactional
    public void create(City city) {
        cityDAO.create(city);
    }

    @Override
    public boolean cityUniqueness(String name) {
        return cityDAO.cityUniqueness(name);
    }

    public Map<String, String> getMessages(City city) {
        Map<String, String> messages = new HashMap<>();
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();
        Set<ConstraintViolation<City>> violations = validator.validate(city);
        for (ConstraintViolation<City> violation : violations) {
            messages.put(String.valueOf(violation.getPropertyPath()), violation.getMessage());
        }
        return messages;
    }

    @Override
    public City getByName(String name) {
        return cityDAO.getByName(name);
    }

    @Transactional
    @Override
    public void update(City city) {
        cityDAO.update(city);
    }
}
