package com.softserveinc.ch067.easypay.controller.swagger;

import com.softserveinc.ch067.easypay.dto.ScheduleItemReadDTO;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import springfox.documentation.annotations.ApiIgnore;

@Api(value = "Inspector schedule", tags = {"Inspector Schedule Controller"}, description = "Controller for the work of the inspector with schedule")
public abstract class InspectorScheduleSwagger {

    @ApiOperation(value = "View a list of available schedule items for an authorized inspector",
            notes = "The inspector must be authorized",
            response = ScheduleItemReadDTO.class
    )
    public abstract Iterable<ScheduleItemReadDTO> getScheduleItemsByAuthUserId(@ApiIgnore @AuthenticationPrincipal User user);

}
