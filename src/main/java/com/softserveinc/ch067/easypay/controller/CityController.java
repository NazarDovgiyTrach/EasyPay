package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.model.City;
import com.softserveinc.ch067.easypay.model.Street;
import com.softserveinc.ch067.easypay.service.ICityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/cities")
public class CityController {
    private final ICityService cityService;

    @Autowired
    public CityController(ICityService cityService) {
        this.cityService = cityService;
    }

    @GetMapping
    public Set<City> getCities() {
        return cityService.getAll();
    }

    @GetMapping("/get/city")
    public City getCity(@RequestParam("id") Long id) {
        return cityService.getById(id);
    }

    @GetMapping("/get-streets-by-id/{id}")
    public Set<Street> getStreetByCityId(@PathVariable(name = "id") Long id) {
        return cityService.getAllStreets(id);
    }
}
