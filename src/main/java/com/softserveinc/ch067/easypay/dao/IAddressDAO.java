package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.*;

public interface IAddressDAO extends IModel<Address> {
    Address getById(Long id);

    boolean isUniqueness(Address address);

    Address getAddress(Region region, City city, Street street, House house, Flat flat);

}
