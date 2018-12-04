package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Rating;
import com.softserveinc.ch067.easypay.model.RatingListItem;
import com.softserveinc.ch067.easypay.model.User;

import java.util.List;
import java.util.Set;

public interface IRatingService {

    List<Rating> getAll();

    Rating getById(Long id);

    void create(Rating rating);

    void update(Rating rating);

    void delete(Rating rating);

    void updateUserRating(Long userId);

    Rating getRatingByUserId(Long userId);

    void initialiseUsersRatings(User inspector, Set<User> users);


}
