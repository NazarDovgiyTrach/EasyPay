package com.softserveinc.ch067.easypay.dao.impl;

public enum EntityGraphType {

    FETCH("javax.persistence.fetchgraph"),
    LOAD("javax.persistence.loadgraph");

    private String type;

    EntityGraphType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}