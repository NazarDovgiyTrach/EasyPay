package com.softserveinc.ch067.easypay.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.ScheduleItemHistory;
import com.softserveinc.ch067.easypay.service.IScheduleHistoryService;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Locale;


@RestController
@RequestMapping("/scheduleHistory")
public class ScheduleHistoryController {
    @Autowired
    private IScheduleHistoryService scheduleHistoryService;

    @Autowired
    private IScheduleService scheduleService;

    @Autowired
    @Qualifier("localeMessageSource")
    private MessageSource messageSource;

    private static final ObjectMapper mapper = new ObjectMapper();

    @ApiOperation(value = "Create a schedule history item")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "id", value = "Schedule item id", required = true, dataType = "Long", paramType = "path"),
            @ApiImplicitParam(name = "scheduleItemHistory", value = "Schedule history item object", required = true, dataType = "ScheduleItemHistory", paramType = "body")
    })
    @ApiResponses(value = {
            @ApiResponse(code = 201, message = "Schedule item created successfully"),
            @ApiResponse(code = 403, message = "Access denied to this schedule item"),
            @ApiResponse(code = 404, message = "Schedule item not found")
    })
    @PostMapping(value = "/schedule/item/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> createScheduleHistoryItem(@PathVariable Long id, @RequestBody ScheduleItemHistory scheduleItemHistory, Locale locale) throws JsonProcessingException {
        ScheduleItem scheduleItem = scheduleService.getById(id, true, true);
        scheduleItemHistory.setAddress(scheduleItem.getAddress());
        scheduleItemHistory.setInspector(scheduleItem.getInspector());
        scheduleItemHistory.setEventDate(scheduleItem.getEventDate());
        scheduleHistoryService.create(scheduleItemHistory);

        return ResponseEntity.status(HttpStatus.CREATED).body(mapper.writeValueAsString(messageSource.getMessage("scheduleAddItemSuccess", null, locale)));
    }
}
