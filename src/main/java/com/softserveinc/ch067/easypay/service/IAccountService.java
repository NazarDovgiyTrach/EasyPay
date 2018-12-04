package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.*;
import com.softserveinc.ch067.easypay.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.util.Locale;

public interface IAccountService {

    ResponseEntity<Object> registration(UserValidationDTO userValidationDTO, BindingResult result,
                                        HttpServletRequest request, Locale locale);

    ResponseEntity<Object> login(AuthorizationDto authorizationDto, HttpServletRequest request, Locale locale);

    RedirectView confirmRegistration(String token, Locale locale);

    ResponseEntity<Object> sendMessage(AuthorizationDto authorizationDto, HttpServletRequest request, Locale locale);

    ResponseEntity<Object> sendForgotPasswordToken(String email, HttpServletRequest request, Locale locale);

    RedirectView resetPassword(String token, Locale locale);

    ResponseEntity<Object> changePassword(PasswordResetDto passwordResetDto, User user, HttpServletRequest request,
                                          Locale locale);

    ResponseEntity<Object> registerUser(RegisterUserDTO userDTO, BindingResult result, HttpServletRequest request,
                                        Locale locale);

    RedirectView continueRegistration(String token, Locale locale);

    ResponseEntity<Object> finishRegistration(String token, ContinueUserRegistrationDTO userDTO, BindingResult result,
                                              Locale locale);
}
