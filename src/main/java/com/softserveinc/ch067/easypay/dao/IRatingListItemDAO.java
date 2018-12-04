package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.RatingListItem;

import java.util.List;

public interface IRatingListItemDAO extends IModel<RatingListItem> {

    List<RatingListItem> getRatingListByRater(Long raterId);
    List<RatingListItem> getRatingListByRatedUser(Long raterId);
    RatingListItem getItemByRaterAndRatedUserId(Long raterId, Long ratedUserId);
    List<RatingListItem> getObjects(int firstResult, String extendSQL);
    Long getPages(String extendSQL);
}
