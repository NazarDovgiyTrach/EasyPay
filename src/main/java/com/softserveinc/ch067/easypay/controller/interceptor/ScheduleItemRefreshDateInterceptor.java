package com.softserveinc.ch067.easypay.controller.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
public class ScheduleItemRefreshDateInterceptor extends HandlerInterceptorAdapter {

    private final IScheduleService scheduleService;
    private static final ObjectMapper mapper = new ObjectMapper();
    private final MessageSource messageSource;

    @Autowired
    public ScheduleItemRefreshDateInterceptor(IScheduleService scheduleService, @Qualifier("localeMessageSource") MessageSource messageSource) {
        this.scheduleService = scheduleService;
        this.messageSource = messageSource;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        final Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        Long scheduleItemId = Long.parseLong(pathVariables.get("id"));
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        ScheduleItem scheduleItem = scheduleService.getById(scheduleItemId, true, true);

        if (!user.getId().equals(scheduleItem.getInspector().getId())) {
            response.setContentType("application/json; charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write(mapper.writeValueAsString(messageSource.getMessage("scheduleAddItemErrorForbiden", null, LocaleContextHolder.getLocale())));
            return false;
        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
        final Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        Long scheduleItemId = Long.parseLong(pathVariables.get("id"));
        ScheduleItem scheduleItem = scheduleService.getById(scheduleItemId, true, true);

        if (scheduleItem.getRepeat()) {
            scheduleItem.setEventDate(scheduleItem.getEventDate().plusMonths(1));
            scheduleService.update(scheduleItem);
        } else {
            scheduleService.delete(scheduleItem);
        }
    }
}
