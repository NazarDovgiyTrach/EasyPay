package com.softserveinc.ch067.easypay.controller.swagger;

import com.softserveinc.ch067.easypay.dto.ScheduleItemAddressReadDTO;
import com.softserveinc.ch067.easypay.dto.ScheduleItemCreateUpdateDTO;
import com.softserveinc.ch067.easypay.dto.ScheduleItemReadDTO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import io.swagger.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import springfox.documentation.annotations.ApiIgnore;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Locale;

@Api(value = "Manager schedule", tags = {"Manager Schedule Controller"}, description = "Controller for the work of the manager with schedule")
public abstract class ManagerScheduleSwagger {

    @ApiOperation(value = "View a schedule item")
    public abstract ScheduleItemReadDTO getScheduleItem(@ApiParam(name = "id", value = "Schedule item id", required = true)
                                                 @PathVariable Long id);

    @ApiOperation(value = "Create a schedule item")
    @ApiResponses(value = {
            @ApiResponse(code = 201, message = "Schedule item created successfully")
    })
    public abstract ResponseEntity<String> createScheduleItem(@ApiParam(name = "id", value = "Inspector id", required = true)
                                                              @PathVariable Long id,
                                                              @ApiParam(name = "scheduleItemCreateUpdateDTO", value = "Schedule item object", required = true)
                                                              @Valid @RequestBody ScheduleItemCreateUpdateDTO scheduleItemCreateUpdateDTO,
                                                              @ApiIgnore BindingResult bindingResult,
                                                              @ApiIgnore Locale locale) throws IOException;

    @ApiOperation(value = "Update a schedule item")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Schedule item updated successfully"),
            @ApiResponse(code = 404, message = "Schedule item not found")
    })
    public abstract ResponseEntity<String> updateScheduleItem(@ApiParam(name = "id", value = "Schedule item id", required = true)
                                                              @PathVariable Long id,
                                                              @ApiParam(name = "scheduleItemCreateUpdateDTO", value = "Schedule item object", required = true)
                                                              @Valid @RequestBody ScheduleItemCreateUpdateDTO scheduleItemCreateUpdateDTO,
                                                              @ApiIgnore BindingResult bindingResult,
                                                              @ApiIgnore Locale locale) throws IOException;

    @ApiOperation(value = "Delete a schedule item")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Schedule item deleted successfully"),
            @ApiResponse(code = 404, message = "Schedule item not found")
    })
    public abstract ResponseEntity<String> removeScheduleItem(@ApiParam(name = "id", value = "Schedule item id", required = true)
                                                              @PathVariable Long id,
                                                              @ApiIgnore Locale locale) throws IOException;

    @ApiOperation(value = "View a list of available items for the inspector's schedule", response = ScheduleItemReadDTO.class)
    public abstract Iterable<ScheduleItemReadDTO> getScheduleItemsByInspectorId(@ApiParam(name = "id", value = "Inspector id", required = true)
                                                                         @PathVariable Long id);

    @ApiOperation(value = "View a size of pagination")
    public abstract Long getUnscheduledAddressesServicePaginationSize(@ApiIgnore @AuthenticationPrincipal User user);

    @ApiOperation(value = "View a list unscheduled addresses by page", response = ScheduleItemAddressReadDTO.class)
    public abstract Iterable<ScheduleItemAddressReadDTO> getUnscheduledAddressesServiceByPage(@ApiIgnore @AuthenticationPrincipal User user,
                                                                                              @ApiParam(name = "number", value = "Page number", required = true)
                                                                           @PathVariable int number);
}
