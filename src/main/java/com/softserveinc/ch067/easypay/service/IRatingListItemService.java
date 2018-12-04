package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.UserRatingDTO;
import com.softserveinc.ch067.easypay.model.RatingListItem;
import com.softserveinc.ch067.easypay.model.User;

import java.util.List;

public interface IRatingListItemService {
    List<RatingListItem> getAll();

    RatingListItem getById(Long id);

    void create(RatingListItem ratingListItem);

    void update(RatingListItem ratingListItem);

    void delete(RatingListItem ratingListItem);

    void updateUserRating(User rater, Long ratedUserId, Double ratingValue);

    Long getPages(String extendSQL);

    List<RatingListItem> getObjects(int firstResult, String extendSQL);

    List<UserRatingDTO> getUsersToRate(int firstResult , Long raterId);

    boolean containsRatedUser(final List<RatingListItem> list, final User user);

    boolean containsRater(final List<RatingListItem> list, final User user);

    Long getPagesRater(Long raterId);

    Long getPagesRated(Long ratedUserId);

    List<RatingListItem> getRatingListByRater(int firstResult, Long raterId);

    List<RatingListItem> getRatingListByRatedUser(int firstResult, Long ratedUserId);

    List<RatingListItem> getRatingListByRatedUser(Long ratedUserId);

    List<RatingListItem> getRatingListByRater(Long raterId);

}
