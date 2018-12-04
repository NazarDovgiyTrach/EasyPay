package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.controller.swagger.AccountControllerSwagger;
import com.softserveinc.ch067.easypay.dto.*;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IAccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Locale;

@RestController
public class AccountController extends AccountControllerSwagger {
    private final IAccountService accountService;

    @Autowired
    public AccountController(IAccountService accountService) {
        this.accountService = accountService;
    }

    @ResponseBody
    @PostMapping(value = "/registration", produces = "application/json")
    public ResponseEntity<Object> registration(@Valid @RequestBody UserValidationDTO userValidationDTO,
                                               BindingResult result, HttpServletRequest request, Locale locale) {
        return accountService.registration(userValidationDTO, result, request, locale);
    }

    @PostMapping("/authorization")
    public ResponseEntity<Object> login(@RequestBody AuthorizationDto authorizationDto, HttpServletRequest request,
                                        Locale locale) {
        return accountService.login(authorizationDto, request, locale);
    }

    @GetMapping("/confirmRegistration")
    public RedirectView confirmRegistration(@RequestParam("token") String token, Locale locale) {
        return accountService.confirmRegistration(token, locale);
    }

    @PostMapping("/reactivationToken")
    public ResponseEntity<Object> sendMessage(@RequestBody AuthorizationDto authorizationDto, HttpServletRequest request,
                                              Locale locale) {
        return accountService.sendMessage(authorizationDto, request, locale);
    }

    @PostMapping("/forgotPassword")
    public ResponseEntity<Object> sendForgotPasswordToken(@RequestParam String email, HttpServletRequest request,
                                                          Locale locale) {
        return accountService.sendForgotPasswordToken(email, request, locale);
    }

    @GetMapping("/resetPassword")
    public RedirectView resetPassword(@RequestParam("token") String token, Locale locale) {
        return accountService.resetPassword(token, locale);
    }

    @PostMapping("/changePassword")
    public ResponseEntity<Object> changePassword(@RequestBody PasswordResetDto passwordResetDto,
                                                 @AuthenticationPrincipal User user, HttpServletRequest request,
                                                 Locale locale) {
        return accountService.changePassword(passwordResetDto, user, request, locale);
    }

    @PostMapping(value = "/admin/registration", produces = "application/json")
    public ResponseEntity<Object> registerUser(@Valid @RequestBody RegisterUserDTO userDTO, BindingResult result,
                                               HttpServletRequest request, Locale locale) {
        return accountService.registerUser(userDTO, result, request, locale);
    }

    @GetMapping(value = "/continue")
    public RedirectView continueRegistration(@RequestParam("token") String token, Locale locale) {
        return accountService.continueRegistration(token, locale);
    }

    @PostMapping(value = "/finish-registration")
    public ResponseEntity<Object> finishRegistration(@RequestParam("token") String token,
                                                     @Valid @RequestBody ContinueUserRegistrationDTO userDTO,
                                                     BindingResult result, Locale locale) {
        return accountService.finishRegistration(token, userDTO, result, locale);
    }
}