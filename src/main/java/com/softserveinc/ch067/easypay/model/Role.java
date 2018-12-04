package com.softserveinc.ch067.easypay.model;

public enum Role {
    ADMIN, MANAGER, INSPECTOR, USER, CHANGE_PASSWORD, FINISH_SOCIAL_REGISTRATION;

    public static Role[] names() {
        return new Role[] {ADMIN, MANAGER, INSPECTOR, USER};
    }
}