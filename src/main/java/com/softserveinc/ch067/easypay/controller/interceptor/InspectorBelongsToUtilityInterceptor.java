package com.softserveinc.ch067.easypay.controller.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import com.softserveinc.ch067.easypay.service.IUserService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
public class InspectorBelongsToUtilityInterceptor extends HandlerInterceptorAdapter {

    private static final ObjectMapper mapper = new ObjectMapper();
    @Autowired
    private IUtilityService utilityService;
    @Autowired
    private IUserService userService;
    @Autowired
    private IScheduleService scheduleService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException {
        //get authenticated manager
        User manager = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        //get path variables
        final Map<String, String> pathVariables = (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        //if path variables contains anything
        if (pathVariables != null) {
            //if path variables does not contain id return false
            if (!pathVariables.containsKey("id")) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write(mapper.writeValueAsString("Wrong input data"));
                return false;
            }
            //if path does not contain "inspector" then path variable is schedule item id
            if (!request.getRequestURL().toString().contains("/inspector/")) {
                Long scheduleId = Long.parseLong(pathVariables.get("id"));
                User inspector = scheduleService.getById(scheduleId, false, true).getInspector();
                return checkIfInspectorBelongs(manager, inspector, response);
            }
            //if path contains "inspector" then path variable is inspector id
            Long inspectorId = Long.parseLong(pathVariables.get("id"));
            User inspector = userService.getById(inspectorId);
            return checkIfInspectorBelongs(manager, inspector, response);
        }

        //if path variables contains nothing then search for id in path
        String path = request.getRequestURL().toString();
        //if path does not contain "inspector" return false
        if (!path.contains("/inspector/")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(mapper.writeValueAsString("im here"));
            return false;
        }
        //if path contains  "inspector" then  search for id in path
        try {
            long inspectorId;
            String pathPart = path.substring(path.indexOf("/inspector/") + "/inspector/".length());
            if (!pathPart.contains("/")) {
                inspectorId = Long.parseLong(pathPart);
            } else {
                inspectorId = Long.parseLong(pathPart.substring(0, pathPart.indexOf("/")));
            }
            User inspector = userService.getById(inspectorId);
            return checkIfInspectorBelongs(manager, inspector, response);
        } catch (NumberFormatException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(mapper.writeValueAsString("Wrong input data"));
            return false;
        }

    }

    private boolean checkIfInspectorBelongs(User manager, User inspector, HttpServletResponse response) throws IOException {
        Utility inspectorUtility = utilityService.getUtilityByInspector(inspector);
        if (inspectorUtility == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write(mapper.writeValueAsString("Inspector does not belong to your utility"));
            return false;
        }
        Utility managerUtility = utilityService.getUtilityByManager(manager,true,false,false);
        if (!inspectorUtility.equals(managerUtility)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write(mapper.writeValueAsString("Inspector does not belong to your utility"));
            return false;
        }
        return true;
    }

}
