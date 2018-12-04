package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IFlatDAO;
import com.softserveinc.ch067.easypay.model.Flat;
import com.softserveinc.ch067.easypay.service.IFlatService;
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
public class FlatServiceImpl implements IFlatService {
    private final IFlatDAO flatDAO;

    @Autowired
    public FlatServiceImpl(IFlatDAO flatDAO) {
        this.flatDAO = flatDAO;
    }

    @Override
    public Set<Flat> getAll() {
        return flatDAO.getAllNumbers();
    }

    @Override
    public Flat getById(Long id) {
        return flatDAO.getById(id);
    }

    @Override
    @Transactional
    public void create(Flat flat) {
        flatDAO.create(flat);
    }

    @Override
    public boolean isUniqueness(String number, Long houseId) {
        return flatDAO.isUniqueness(number, houseId);
    }

    public Map<String, String> getMessages(Flat flat) {
        Map<String, String> messages = new HashMap<>();
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();
        Set<ConstraintViolation<Flat>> violations = validator.validate(flat);
        for (ConstraintViolation<Flat> violation : violations) {
            messages.put(String.valueOf(violation.getPropertyPath()), violation.getMessage());
        }
        return messages;
    }

    @Override
    public Flat getByNumberAndHouseId(String name, Long houseId) {
        return flatDAO.getByNumberAndHouseId(name, houseId);
    }

    @Transactional
    @Override
    public void update(Flat flat) {
        flatDAO.update(flat);
    }
}
