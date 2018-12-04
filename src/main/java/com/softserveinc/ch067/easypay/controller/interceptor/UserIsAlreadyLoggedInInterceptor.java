package com.softserveinc.ch067.easypay.controller.interceptor;

import org.apache.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class UserIsAlreadyLoggedInInterceptor extends HandlerInterceptorAdapter {
    private String redirectURL = "/home";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (!(auth instanceof AnonymousAuthenticationToken)) {
            response.setStatus(HttpStatus.SC_TEMPORARY_REDIRECT);
            response.setHeader("Location",
                    response.encodeRedirectURL(request.getContextPath() + redirectURL));
            return false;
        }

        return true;
    }
}
