package com.softserveinc.ch067.easypay.controller.swagger;

import com.softserveinc.ch067.easypay.dto.PriceHistoryDTO;
import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.NewPrice;
import com.softserveinc.ch067.easypay.model.User;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import springfox.documentation.annotations.ApiIgnore;

import javax.validation.Valid;

public abstract class ManagerControllerSwagger {
    @ApiOperation(value = "View current price for the utility")
    public abstract CurrentPrice getCurrentPriceForManager(@ApiIgnore @AuthenticationPrincipal User currentUser);

    @ApiOperation(value = "Update utility`s current price")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Current price updated successfully"),
            @ApiResponse(code = 400, message = "User entered invalid data")
    })
    public abstract ResponseEntity updateCurrentPrice(@ApiParam(name = "newPrice", value = "Current price object with price value which will be set", required = true)
                                      @Valid @RequestBody CurrentPrice newPrice,
                                      @ApiIgnore BindingResult result);


    @ApiOperation(value = "Create new current price for the utility. The old price gets inactive")
    @ApiResponses(value = {
            @ApiResponse(code = 201, message = "New price created successfully"),
            @ApiResponse(code = 400, message = "User entered invalid data")
    })
    public abstract ResponseEntity addCurrentPrice(@ApiParam (name = "newPrice", value = "Current price object with price value which will be set", required = true)
                                   @Valid @RequestBody CurrentPrice newPrice,
                                   @ApiIgnore BindingResult result);


    @ApiOperation(value = "View price history chart for the utility")
    public abstract PriceHistoryDTO getPriceHistory(@ApiParam (name = "startDate", value = "Start date for the chart pagination view", required = true)
                                    @RequestParam(name = "startDate") String startDate,
                                    @ApiParam (name = "targerDate", value = "Target date for the chart pagination view", required = true)
                                    @RequestParam(name = "targetDate") String targetDate,
                                    @ApiIgnore @AuthenticationPrincipal User currentUser);


    @ApiOperation(value = "View future price which will be set on a specific date if exist")
    public abstract NewPrice getNewPriceByUtilityId(@ApiIgnore @AuthenticationPrincipal User currentUser);


    @ApiOperation(value = "Update future price for the current utility")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Future price updated successfully"),
            @ApiResponse(code = 400, message = "User entered invalid data")
    })
    public abstract ResponseEntity saveNewPriceActivation(@ApiParam (name = "newPrice", value = "NewPrice object which contains future price value and activation date", required = true)
                                          @Valid @RequestBody NewPrice newPrice,
                                          @ApiIgnore BindingResult result);
}
