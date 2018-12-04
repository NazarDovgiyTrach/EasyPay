package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.model.City;
import com.softserveinc.ch067.easypay.model.Region;
import com.softserveinc.ch067.easypay.service.IRegionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/regions")
public class RegionController {

    private final IRegionService regionService;

    @Autowired
    public RegionController(IRegionService regionService){
     this.regionService = regionService;
    }

    @GetMapping()
    public Set<Region> getRegions() {
        return regionService.getAllRegionNames();
    }

    @GetMapping("/get/region")
    public Region getRegion(@RequestParam(name = "id") Long id) {
        return regionService.getById(id);
    }

    @GetMapping("/get-cities-by-id/{id}")
    public Set<City> getRegionCities(@PathVariable(name = "id") Long id) {
        return regionService.getAllCities(id);
    }
}
