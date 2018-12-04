package com.softserveinc.ch067.easypay.controller.swagger;

import com.softserveinc.ch067.easypay.dto.AuthorizationDto;
import com.softserveinc.ch067.easypay.dto.PasswordResetDto;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.response.AuthorizationResponse;
import io.swagger.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import springfox.documentation.annotations.ApiIgnore;

import javax.servlet.http.HttpServletRequest;
import java.util.Locale;

@Api(value = "Authorization", tags = "Authorization Controller", description = "Controller for work with user's authorization")
public abstract class AccountControllerSwagger {

    @ApiOperation(value = "Send password reset token to email")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Password reset token successfully sent", response = ResponseEntity.class),
            @ApiResponse(code = 400, message = "User with current email does not exist or blocked", response = ResponseEntity.class)
    })
    public abstract ResponseEntity<Object> sendForgotPasswordToken(@ApiParam(name = "email", value = "User's email", required = true) String email,
                                                                   @ApiIgnore HttpServletRequest request,
                                                                   @ApiIgnore Locale locale);


    @ApiOperation(value = "Verify password reset token and redirect depends on token validate")
    public abstract RedirectView resetPassword(@ApiParam(name = "token", value = "Password reset token", required = true) String token,
                                               @ApiIgnore Locale locale);

    @ApiOperation("User login")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Login success", response = ResponseEntity.class),
            @ApiResponse(code = 403, message = "Incorrect password or email", response = ResponseEntity.class),
            @ApiResponse(code = 401, message = "Account is banned or does not confirmed", response = ResponseEntity.class)
    })
    public abstract ResponseEntity<Object> login(@ApiParam(name = "authorizationDto", value = "DTO which includes email and password", required = true) AuthorizationDto authorizationDto,
                                                 @ApiIgnore HttpServletRequest request,
                                                 @ApiIgnore Locale locale);
    @ApiOperation("User change password")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Password successfully updated", response = ResponseEntity.class),
            @ApiResponse(code = 400, message = "Password conformation does not match or password is not valid", response = ResponseEntity.class)
    })
    public abstract ResponseEntity<Object> changePassword(@ApiParam(name = "passwordResetDto", value = "DTO which include password and conform password", required = true) PasswordResetDto passwordResetDto,
                                                          @ApiIgnore User user,
                                                          @ApiIgnore HttpServletRequest request,
                                                          @ApiIgnore Locale locale);
}
