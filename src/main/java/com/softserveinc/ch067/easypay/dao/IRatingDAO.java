package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.Rating;

import java.util.List;

public interface IRatingDAO extends IModel<Rating> {

    Rating getRatingByUserId(Long userId);
    List<Rating> getObjects(int firstResult, String extendSQL);
    Long getPages(String extendSQL);

}
