package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.controller.swagger.AdminControllerSwagger;
import com.softserveinc.ch067.easypay.dto.UpdateUserDTO;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(value = "/admin")
public class AdminController extends AdminControllerSwagger {

    private final IUserService userService;

    @Autowired
    public AdminController(IUserService userService) {
        this.userService = userService;
    }

    /**
     * This method serves for updating users role and making users active/not active.
     * @param userDTO - instance, which includes three user fields - id, role and active.
     */
    @PutMapping(value = "/users/update")
    public void updateUser(@RequestBody UpdateUserDTO userDTO) {
        userService.update(userDTO);
    }

    /**
     * This method get pages count for admin pagination.
     *
     * @param user - authorized user.
     * @return count of pages for users.
     */
    @GetMapping("/pages")
    public Long showPages(@AuthenticationPrincipal User user) {
        return userService.getPages(user.getId());
    }

    /**
     * This method return users, for specific page.
     *
     * @param firstResult
     * @param user - authorized user.
     * @return
     */
    @GetMapping("/users")
    public List<User> getUsers(@RequestParam(value = "firstResult") Integer firstResult,
                               @AuthenticationPrincipal User user) {
        return userService.getObjects(firstResult, user.getId());
    }
}