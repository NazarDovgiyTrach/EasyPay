package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.UnscheduledAddresses;
import com.softserveinc.ch067.easypay.model.User;

import java.util.List;

public interface IUnscheduledAddressesDAO extends IModel<UnscheduledAddresses> {

    List<UnscheduledAddresses> getByUtilityId(Long utilityId, EntityGraphType type, String... attributeGraph);

    List<Address> getAddressListByUtilityId(Long id);

    List<Address> getObjects(Long utilityId, int firstResult);

    Long getPages(Long utilityId);

}
