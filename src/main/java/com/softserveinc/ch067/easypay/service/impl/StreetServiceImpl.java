package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IScheduleItemDAO;
import com.softserveinc.ch067.easypay.dao.IStreetDAO;
import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.House;
import com.softserveinc.ch067.easypay.model.Street;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import com.softserveinc.ch067.easypay.service.IStreetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class StreetServiceImpl implements IStreetService {
    private final IStreetDAO streetDAO;
    private final IScheduleItemDAO scheduleItemDAO;

    @Autowired
    public StreetServiceImpl(IStreetDAO streetDAO, IScheduleItemDAO scheduleItemDAO) {
        this.streetDAO = streetDAO;
        this.scheduleItemDAO = scheduleItemDAO;
    }

    @Override
    public Set<Street> getAll() {
        return streetDAO.getAllNames();
    }

    @Override
    public Street getById(Long id) {
        return streetDAO.getById(id);
    }

    @Override
    public Set<House> getAllHouses(Long id) {
        return streetDAO.getById(id).getHouses();
    }

    @Override
    @Transactional
    public void create(Street street) {
        streetDAO.create(street);
    }

    @Override
    public boolean isUniqueness(String name, Long cityId) {
        return streetDAO.isUniqueness(name, cityId);
    }

    public Map<String, String> getMessages(Street street) {
        Map<String, String> messages = new HashMap<>();
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        Validator validator = factory.getValidator();
        Set<ConstraintViolation<Street>> violations = validator.validate(street);
        for (ConstraintViolation<Street> violation : violations) {
            messages.put(String.valueOf(violation.getPropertyPath()), violation.getMessage());
        }
        return messages;
    }

    @Override
    public List<Street> getStreetsByAuthInspectorId(Long id) {
        return scheduleItemDAO.getListByUserId(id, EntityGraphType.FETCH, "address")
                .stream()
                .map(el -> el.getAddress().getStreet()).collect(Collectors.toList());
    }

    @Override
    public Street getByNameAndCityId(String name, Long cityId) {
        return streetDAO.getByNameAndCityId(name, cityId);
    }

    @Transactional
    @Override
    public void update(Street street) {
        streetDAO.update(street);
    }
}
