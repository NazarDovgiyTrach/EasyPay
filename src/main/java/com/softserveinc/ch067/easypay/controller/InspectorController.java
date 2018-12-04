package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.dto.UtilityCountersDTO;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.IAddressService;
import com.softserveinc.ch067.easypay.service.ICounterService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class InspectorController {
    private final IUtilityService utilityService;
    private final IAddressService addressService;
    private final ICounterService counterService;

    @Autowired
    public InspectorController(IUtilityService utilityService, IAddressService addressService, ICounterService counterService, ModelMapper modelMapper) {
        this.utilityService = utilityService;
        this.addressService = addressService;
        this.counterService = counterService;
    }

    @GetMapping("/inspector/address/{id}/counters")
    ResponseEntity<Object> getCountersByAddressIdAndUtility(@PathVariable("id") Long id,
                                                            @AuthenticationPrincipal User user){
        Utility utility = utilityService.getUtilityByInspectorWithCounters(user);
        List<Counter> counters = counterService.getCountersByAddressIdAndUtility(id, utility);

        UtilityCountersDTO utilityCounters = new UtilityCountersDTO();
        utilityCounters.setUtilityName(utility.getName());
        utilityCounters.setCounters(counters);

        return new ResponseEntity<>(utilityCounters, HttpStatus.OK);
    }

    @GetMapping("/inspector/addresses")
    public List<Address> getAddressesByAuthInspector(@AuthenticationPrincipal User user){
        return addressService.getAddressesByInspectorId(user.getId());
    }
}
