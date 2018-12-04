package com.softserveinc.ch067.easypay.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.softserveinc.ch067.easypay.additional.ErrorMessages;
import com.softserveinc.ch067.easypay.controller.swagger.ManagerScheduleSwagger;
import com.softserveinc.ch067.easypay.dto.ScheduleItemAddressCreateUpdateDTO;
import com.softserveinc.ch067.easypay.dto.ScheduleItemAddressReadDTO;
import com.softserveinc.ch067.easypay.dto.ScheduleItemCreateUpdateDTO;
import com.softserveinc.ch067.easypay.dto.ScheduleItemReadDTO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import com.softserveinc.ch067.easypay.service.IUnscheduledAddressesService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Collection;
import java.util.Locale;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/manager")
public class ManagerScheduleController extends ManagerScheduleSwagger {
    private final ErrorMessages errorMessages;
    private final IScheduleService scheduleService;
    private final IUnscheduledAddressesService unscheduledAddressesService;
    private final IUtilityService utilityService;
    private static final ObjectMapper mapper = new ObjectMapper();
    private final MessageSource messageSource;
    private final ModelMapper modelMapper;

    @Autowired
    public ManagerScheduleController(IScheduleService scheduleService,
                                     ErrorMessages errorMessages,
                                     IUnscheduledAddressesService unscheduledAddressesService,
                                     IUtilityService utilityService,
                                     @Qualifier("localeMessageSource") MessageSource messageSource, ModelMapper modelMapper) {
        this.scheduleService = scheduleService;
        this.errorMessages = errorMessages;
        this.unscheduledAddressesService = unscheduledAddressesService;
        this.utilityService = utilityService;
        this.messageSource = messageSource;
        this.modelMapper = modelMapper;
    }

    @GetMapping(value = "/schedule/item/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ScheduleItemReadDTO getScheduleItem(@PathVariable Long id) {
        ScheduleItem scheduleItem = scheduleService.getById(id, true, false);
        return modelMapper.map(scheduleItem, ScheduleItemReadDTO.class);
    }

    @PostMapping(value = "/schedule/item/inspector/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> createScheduleItem(@PathVariable Long id,
                                                     @Valid @RequestBody ScheduleItemCreateUpdateDTO scheduleItemCreateUpdateDTO,
                                                     BindingResult bindingResult,
                                                     Locale locale) throws IOException {
        if (bindingResult.hasErrors()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapper.writeValueAsString(errorMessages.getErrorMessagesWithKeys(bindingResult)));
        }

        ScheduleItem scheduleItem = modelMapper.map(scheduleItemCreateUpdateDTO, ScheduleItem.class);
        scheduleItem.setInspector(new User(id));
        scheduleService.create(scheduleItem);

        return ResponseEntity.status(HttpStatus.CREATED).body(mapper.writeValueAsString(messageSource.getMessage("scheduleItemCreateSuccess", null, locale)));
    }

    @PutMapping(value = "/schedule/item/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> updateScheduleItem(@PathVariable Long id,
                                                     @Valid @RequestBody ScheduleItemCreateUpdateDTO scheduleItemCreateUpdateDTO,
                                                     BindingResult bindingResult,
                                                     Locale locale) throws IOException {

        if (bindingResult.hasErrors()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(mapper.writeValueAsString(errorMessages.getErrorMessagesWithKeys(bindingResult)));
        }

        ScheduleItem scheduleItem = scheduleService.getById(id, true, false);
        BeanUtils.copyProperties(scheduleItemCreateUpdateDTO, scheduleItem);
        BeanUtils.copyProperties(scheduleItemCreateUpdateDTO.getAddress(), scheduleItem.getAddress());

        scheduleService.update(scheduleItem);

        return ResponseEntity.status(HttpStatus.OK).body(mapper.writeValueAsString(messageSource.getMessage("scheduleItemUpdateSuccess", null, locale)));
    }

    @DeleteMapping(value = "/schedule/item/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> removeScheduleItem(@PathVariable Long id, Locale locale) throws IOException {
        scheduleService.delete(id);
        return ResponseEntity.status(HttpStatus.OK).body(mapper.writeValueAsString(messageSource.getMessage("scheduleItemDeleteSuccess", null, locale)));
    }


    @GetMapping(value = "/schedule/item/list/inspector/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Iterable<ScheduleItemReadDTO> getScheduleItemsByInspectorId(@PathVariable Long id) {

        return scheduleService.getListByUserId(id, true, false)
                .stream()
                .map(i -> modelMapper.map(i, ScheduleItemReadDTO.class))
                .collect(Collectors.toList());
    }

    @GetMapping(value = "/schedule/unscheduled/pagination/size", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Long getUnscheduledAddressesServicePaginationSize(@AuthenticationPrincipal User user) {
        Utility utility = utilityService.getUtilityByManager(user,false,false,false);

        return unscheduledAddressesService.getPages(utility.getId());
    }

    @GetMapping(value = "/schedule/unscheduled/list/page/{number}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Iterable<ScheduleItemAddressReadDTO> getUnscheduledAddressesServiceByPage(@AuthenticationPrincipal User user, @PathVariable int number) {
        Utility utility = utilityService.getUtilityByManager(user,false,false,false);

        return unscheduledAddressesService.getObjects(utility.getId(), number > 1 ? (number - 1) * 10 : 0)
                .stream()
                .map(i -> modelMapper.map(i, ScheduleItemAddressReadDTO.class))
                .collect(Collectors.toList());
    }
}
