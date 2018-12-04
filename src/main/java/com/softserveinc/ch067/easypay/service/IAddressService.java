package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.AddressDTO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.User;

import java.util.List;

public interface IAddressService {

    List<Address> getAll();

    void save(Address address);

    void disconnect(Long id);

    void connect(Long id);

    Address getById(Long id);

    List<Address> getAddressesByInspectorId(Long id);

    void addUserAddress(AddressDTO addressDTO, User user);

    Long addUtilityAddress(AddressDTO addressDTO);
}
