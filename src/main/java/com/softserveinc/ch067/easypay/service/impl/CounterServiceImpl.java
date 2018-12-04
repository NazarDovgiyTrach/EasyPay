package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.ICounterDAO;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.Debt;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.ICounterService;
import com.softserveinc.ch067.easypay.service.ICurrentPriceService;
import com.softserveinc.ch067.easypay.service.IDebtService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.*;

@Service
public class CounterServiceImpl implements ICounterService {

    private final ICounterDAO counterDAO;

    private final IDebtService debtService;

    private final IUtilityService utilityService;

    private final ICurrentPriceService currentPriceService;

    @Autowired
    public CounterServiceImpl(ICounterDAO counterDAO,
                              IDebtService debtService,
                              @Lazy IUtilityService utilityService,
                              ICurrentPriceService currentPriceService) {
        this.counterDAO = counterDAO;
        this.debtService = debtService;
        this.utilityService = utilityService;
        this.currentPriceService = currentPriceService;
    }

    @Override
    public List<Counter> getAll() {
        return counterDAO.getAll();
    }

    @Transactional
    @Override
    public void create(Counter counter) {
        counterDAO.create(counter);
    }

    @Override
    public List<Counter> getAllByUserId(Long id) {
        return counterDAO.getAllByUserId(id);
    }

    @Transactional
    @Override
    public void update(Counter counter) {
        counterDAO.update(counter);
    }

    @Transactional
    @Override
    public void updateCounterCurrentValue(Long id, Long newValue) {
        Counter databaseCounter = getById(id);
        Utility utility = utilityService.getUtilityByCounter(databaseCounter);
        Debt debt = debtService.getDebtByUtilityAndAddress(utility.getId(), databaseCounter.getAddress().getId());
        CurrentPrice price = currentPriceService.getCurrentPriceByUtility(utility);
        if (databaseCounter.getOldValue().equals(databaseCounter.getCurrentValue())){
            databaseCounter.setCurrentValue(newValue);
            debt.setValue(debt.getValue() + (databaseCounter.getCurrentValue() - databaseCounter.getOldValue()) * price.getPrice());
        }else{
            debt.setValue(debt.getValue() + (newValue - databaseCounter.getCurrentValue())* price.getPrice());
            databaseCounter.setCurrentValue(newValue);
        }
        if (debt.getValue() <= 0){
            debt.setLastPaid(LocalDate.now());
            databaseCounter.setOldValue(databaseCounter.getCurrentValue());
        }
        databaseCounter.setLastUpdated(LocalDate.now());
        debtService.update(debt);
        update(databaseCounter);
    }



    @Transactional
    @Override
    public void updateCounterStatus(Long id, boolean active) {
        Counter databaseCounter = getById(id);
        databaseCounter.setActive(active);
        update(databaseCounter);
    }

    @Transactional
    @Override
    public void updateCounterType(Long id, boolean fixed) {
        Counter databaseCounter = getById(id);
        boolean wasActivated = !(databaseCounter.getOldValue().equals(0l) && databaseCounter.getCurrentValue().equals(0l));

        if (wasActivated) {
            if (databaseCounter.isFixed() && !fixed) {
                databaseCounter.setOldValue(1l);
                databaseCounter.setCurrentValue(1l);
            } else if (!databaseCounter.isFixed() && fixed) {
                databaseCounter.setOldValue(0l);
                databaseCounter.setCurrentValue(1l);
            }
        }

        databaseCounter.setFixed(fixed);
        update(databaseCounter);
    }

    @Transactional
    @Override
    public void initWithValues(Counter counter) {
        if (counter.isFixed()) {
            counter.setOldValue(0L);
            counter.setCurrentValue(1L);
        }else{
            counter.setOldValue(1L);
            counter.setCurrentValue(1L);
        }

        update(counter);
    }

    @Override
    public Counter getById(Long id) {
        return counterDAO.getById(id);
    }

    @Override
    public List<Counter> getCountersByAddressIdAndUtility(Long id, Utility utility) {
        List<Counter> databaseCounters = counterDAO.getCountersByAddressId(id);
        List<Counter> finalCounters = new ArrayList<>();

        for (Counter counter : databaseCounters)
            if (utility.getCounters().contains(counter))
                finalCounters.add(counter);

        return finalCounters;

    }

    @Override
    public List<Counter> getFixedCounterForRegularPay(LocalDate beforeDate, int maxResults) {
        return counterDAO.getFixedCounterForRegularPay(beforeDate, maxResults);
    }
}
