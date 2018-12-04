package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IHouseDAO;
import com.softserveinc.ch067.easypay.model.Flat;
import com.softserveinc.ch067.easypay.model.House;
import com.softserveinc.ch067.easypay.service.IHouseService;
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
public class HouseServiceImpl implements IHouseService {
    private final IHouseDAO houseDAO;

    @Autowired
    public HouseServiceImpl(IHouseDAO houseDAO) {
        this.houseDAO = houseDAO;
    }

    @Override
    public Set<House> getAll() {
        return houseDAO.getAllNumbers();
    }

    @Override
    public House getById(Long id) {
        return houseDAO.getById(id);
    }

    @Override
    public Set<Flat> getAllFlats(Long id) {
        return houseDAO.getById(id).getFlats();
    }

    @Override
    @Transactional
    public void create(House house) {
        houseDAO.create(house);
    }

    @Override
    public boolean isUniqueness(String number, Long streetId) {
        return houseDAO.isUniqueness(number, streetId);
    }

    public Map<String, String> getMessages(House house) {
        Map<String, String> messages = new HashMap<>();
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();
        Set<ConstraintViolation<House>> violations = validator.validate(house);
        for (ConstraintViolation<House> violation : violations) {
            messages.put(String.valueOf(violation.getPropertyPath()), violation.getMessage());
        }
        return messages;
    }

    @Override
    public House getByNumberAndStreetId(String number, Long streetId) {
        return houseDAO.getByNumberAndStreetId(number, streetId);
    }
    @Transactional
    @Override
    public void update(House house) {
        houseDAO.update(house);
    }
}
