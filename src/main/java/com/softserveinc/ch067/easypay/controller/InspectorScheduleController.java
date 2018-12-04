package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.controller.swagger.InspectorScheduleSwagger;
import com.softserveinc.ch067.easypay.dto.ScheduleItemReadDTO;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/inspector")
public class InspectorScheduleController extends InspectorScheduleSwagger {
    private final ModelMapper modelMapper;
    private final IScheduleService scheduleService;

    @Autowired
    public InspectorScheduleController(IScheduleService scheduleService, ModelMapper modelMapper) {
        this.scheduleService = scheduleService;
        this.modelMapper = modelMapper;
    }

    @GetMapping(value = "/schedule/item/list", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Iterable<ScheduleItemReadDTO> getScheduleItemsByAuthUserId(@AuthenticationPrincipal User user) {
        return scheduleService.getListByUserId(user.getId(), true, false)
                .stream()
                .map(i -> modelMapper.map(i, ScheduleItemReadDTO.class))
                .collect(Collectors.toList());
    }
}
