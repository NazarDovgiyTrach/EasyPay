package com.softserveinc.ch067.easypay.additional;

import com.softserveinc.ch067.easypay.dto.ContinueUserRegistrationDTO;
import com.softserveinc.ch067.easypay.dto.RegisterUserDTO;
import com.softserveinc.ch067.easypay.dto.UserValidationDTO;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import java.util.*;

@Component
public class ErrorMessages {

    private final IUserService userService;

    private final MessageSource messageSource;

    @Autowired
    public ErrorMessages(@Lazy IUserService userService,
                         @Qualifier(value = "localeMessageSource") MessageSource messageSource) {
        this.userService = userService;
        this.messageSource = messageSource;
    }


    public Map<String, String> getErrorMessagesWithKeys(BindingResult result) {
        Map<String, String> messages = new HashMap<>();
        for (ObjectError error : result.getAllErrors()) {
            FieldError fieldError = (FieldError) error;
            messages.put(fieldError.getField(), error.getDefaultMessage());
        }
        return messages;
    }

    public Map<String, String> buildResponse(UserValidationDTO user, BindingResult result, Locale locale) {
        Map<String, String> messages = getErrorMessagesWithKeys(result);
        if (!userService.isPasswordValid(user.getPassword())) {
            messages.put("password", messageSource.getMessage("invalidPassword", null, locale));
        }
        if (!userService.isEmailUnique(user.getEmail())) {
            messages.put("email", messageSource.getMessage("notUniqueEmail", null, locale));
        }
        return messages;
    }

    public Map<String, String> buildResponse(ContinueUserRegistrationDTO user, BindingResult result, Locale locale) {
        return getErrorMessagesWithKeys(result);
    }

    public Map<String, String> buildResponse(RegisterUserDTO user, BindingResult result, Locale locale) {
        Map<String, String> messages = getErrorMessagesWithKeys(result);
        System.out.println(messages.toString());
        if (!userService.isEmailUnique(user.getEmail())) {
            messages.put("email", messageSource.getMessage("notUniqueEmail", null, locale));
        }
        return messages;
    }

    public List<String> getErrorMessages(BindingResult result) {
        List<String> messages = new ArrayList<>();
        for (ObjectError error : result.getAllErrors()) {
            messages.add(error.getDefaultMessage());
        }
        return messages;
    }
}
