package com.softserveinc.ch067.easypay.controller.swagger;

import com.softserveinc.ch067.easypay.dto.UpdateUserDTO;
import com.softserveinc.ch067.easypay.model.User;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import springfox.documentation.annotations.ApiIgnore;

import java.util.List;

public abstract class AdminControllerSwagger {

    @ApiOperation(value = "Update user status or role")
    public abstract void updateUser(@ApiParam(name = "updated user", value = "user") UpdateUserDTO userDTO);

    @ApiOperation(value = "Get count of pages for user list")
    public abstract Long showPages(@ApiIgnore User user);

    @ApiOperation(value = "Get users for one page")
    public abstract List<User> getUsers(@ApiParam Integer firstResult,
                                        @ApiIgnore User user);
}
