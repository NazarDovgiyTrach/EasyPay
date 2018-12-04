package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.model.House;
import com.softserveinc.ch067.easypay.model.Street;
import com.softserveinc.ch067.easypay.service.IStreetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/streets")
public class StreetController {

    private final IStreetService streetService;

    @Autowired
    public StreetController(IStreetService streetService) {
        this.streetService = streetService;
    }

    @GetMapping
    public Set<Street> streets() {
        return streetService.getAll();
    }

    @GetMapping("/get/street")
    public Street getFlat(@RequestParam(name = "id") Long id) {
        return streetService.getById(id);
    }

    @GetMapping("/get-houses-by-id/{id}")
    public Set<House> getHousesByStreetId(@PathVariable(name = "id") Long id) {
        return streetService.getAllHouses(id);
    }
}
