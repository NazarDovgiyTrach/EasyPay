package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.model.Flat;
import com.softserveinc.ch067.easypay.service.IFlatService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping("/flats")
public class FlatController {
    private final IFlatService flatService;

    @Autowired
    public FlatController(IFlatService flatService) {
        this.flatService = flatService;
    }

    @GetMapping("/flats")
    public Set<Flat> flats() {
        return flatService.getAll();
    }

    @GetMapping("/get/flat")
    public Flat getFlat(@RequestParam("id") Long id) {
        return flatService.getById(id);
    }
}
