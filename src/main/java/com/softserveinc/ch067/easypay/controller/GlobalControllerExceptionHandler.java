package com.softserveinc.ch067.easypay.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;

import javax.servlet.http.HttpServletRequest;

@ControllerAdvice
public class GlobalControllerExceptionHandler {

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(value = HttpStatus.NOT_FOUND)
    public ModelAndView handleError404(HttpServletRequest request, Exception ex) {
        return new ModelAndView("/resources/html/errors/404.html");
    }
    
    /*@ExceptionHandler(Exception.class)
    public ModelAndView handleError(HttpServletRequest request, Exception ex) {
        return new ModelAndView("/resources/html/errors/500.html");
    }*/
}
