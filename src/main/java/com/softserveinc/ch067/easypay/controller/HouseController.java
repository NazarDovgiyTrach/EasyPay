package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.model.Flat;
import com.softserveinc.ch067.easypay.model.House;
import com.softserveinc.ch067.easypay.service.IHouseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/houses")
public class HouseController {
    private final IHouseService houseService;

    @Autowired
    public HouseController(IHouseService houseService) {
        this.houseService = houseService;
    }


    @GetMapping("/houses")
    public Set<House> houses() {
        return houseService.getAll();
    }

    @GetMapping("/get/house")
    public House getFlat(@RequestParam("id") Long id) {
        return houseService.getById(id);
    }

    @GetMapping(value = "/get-flats-by-id/{id}")
    public Set<Flat> getAllFlats(@PathVariable(name = "id")Long id){
        return houseService.getAllFlats(id);
    }
}
