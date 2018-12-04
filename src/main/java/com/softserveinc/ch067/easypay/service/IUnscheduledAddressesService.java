package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.UnscheduledAddresses;
import com.softserveinc.ch067.easypay.model.Utility;

import java.util.List;

public interface IUnscheduledAddressesService {

    List<UnscheduledAddresses> getAll();

    UnscheduledAddresses getById(Long id);

    List<Address> getAddressListByUtilityId(Long id);

    void create(UnscheduledAddresses unscheduledAddresses);

    void update(UnscheduledAddresses unscheduledAddresses);

    void delete(UnscheduledAddresses unscheduledAddresses);

    void delete(Long id);

    List<UnscheduledAddresses> getByUtility(Utility utility, boolean withAddress, boolean withUtility);

    List<Address> getObjects(Long utilityId, int firstResult);

    Long getPages(Long utilityId);

}
