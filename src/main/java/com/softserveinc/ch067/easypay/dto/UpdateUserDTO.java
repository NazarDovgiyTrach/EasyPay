package com.softserveinc.ch067.easypay.dto;

import com.softserveinc.ch067.easypay.model.Role;
import com.softserveinc.ch067.easypay.model.UserStatus;

public class UpdateUserDTO {

    private Long id;

    private Role role;

    private UserStatus status;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }
}
