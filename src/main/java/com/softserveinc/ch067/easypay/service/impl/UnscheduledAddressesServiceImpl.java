package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IUnscheduledAddressesDAO;
import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.UnscheduledAddresses;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.IUnscheduledAddressesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class UnscheduledAddressesServiceImpl implements IUnscheduledAddressesService {
    private final IUnscheduledAddressesDAO unscheduledAddressesDAO;

    @Autowired
    public UnscheduledAddressesServiceImpl(IUnscheduledAddressesDAO unscheduledAddressesDAO) {
        this.unscheduledAddressesDAO = unscheduledAddressesDAO;
    }

    @Override
    @Transactional(readOnly = true)
    public List<UnscheduledAddresses> getAll() {
        return unscheduledAddressesDAO.getAll();
    }

    @Override
    @Transactional(readOnly = true)
    public UnscheduledAddresses getById(Long id) {
        return unscheduledAddressesDAO.getById(id);
    }

    @Override
    public List<Address> getAddressListByUtilityId(Long id) {
        return unscheduledAddressesDAO.getAddressListByUtilityId(id);
    }

    @Override
    @Transactional
    public void create(UnscheduledAddresses unscheduledAddresses) {
        unscheduledAddressesDAO.create(unscheduledAddresses);
    }

    @Override
    @Transactional
    public void update(UnscheduledAddresses unscheduledAddresses) {
        unscheduledAddressesDAO.update(unscheduledAddresses);
    }

    @Override
    @Transactional
    public void delete(UnscheduledAddresses unscheduledAddresses) {
        unscheduledAddressesDAO.delete(unscheduledAddresses);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        UnscheduledAddresses unscheduledAddresses = getById(id);
        unscheduledAddressesDAO.delete(unscheduledAddresses);
    }

    @Override
    public List<UnscheduledAddresses> getByUtility(Utility utility, boolean withAddress, boolean withUtility) {
        List<String> attributeGraph = new ArrayList<>();

        if (withAddress) {
            attributeGraph.add("address");
        }

        if (withUtility) {
            attributeGraph.add("utility");
        }

        return unscheduledAddressesDAO.getByUtilityId(utility.getId(), EntityGraphType.FETCH, attributeGraph.toArray(new String[0]));
    }

    @Override
    public List<Address> getObjects(Long utilityId, int firstResult) {
        return unscheduledAddressesDAO.getObjects(utilityId, firstResult);
    }

    @Override
    public Long getPages(Long utilityId) {
        return unscheduledAddressesDAO.getPages(utilityId);
    }
}
