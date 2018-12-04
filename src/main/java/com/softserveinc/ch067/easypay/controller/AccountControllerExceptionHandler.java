package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.exception.AccountIsBannedException;
import com.softserveinc.ch067.easypay.exception.ConfirmRegistrationJWTInvalidException;
import com.softserveinc.ch067.easypay.exception.PasswordResetJWTInvalidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.view.RedirectView;

@ControllerAdvice(basePackageClasses = {AccountController.class, SocialOAuthController.class})
public class AccountControllerExceptionHandler {

    @ExceptionHandler(PasswordResetJWTInvalidException.class)
    public RedirectView handleInvalidJWTExceptionForPasswordReset(){
        return new RedirectView("/forgotPasswordPage?tokenInvalid");
    }

    @ExceptionHandler(ConfirmRegistrationJWTInvalidException.class)
    public RedirectView handleInvalidJWTExceptionForConfirmRegistration(){
        return new RedirectView("/loginPage?tokenInvalid");
    }

    @ExceptionHandler(AccountIsBannedException.class)
    public RedirectView handleBannedAccountException(){
        return new RedirectView("/loginPage?accountBanned");
    }
}
