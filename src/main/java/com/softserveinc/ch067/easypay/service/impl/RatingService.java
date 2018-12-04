package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IRatingDAO;
import com.softserveinc.ch067.easypay.model.Rating;
import com.softserveinc.ch067.easypay.model.RatingListItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IRatingListItemService;
import com.softserveinc.ch067.easypay.service.IRatingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
public class RatingService implements IRatingService {

    private IRatingDAO ratingDAO;
    private IRatingListItemService ratingListItemService;


    @Autowired
    public RatingService(IRatingDAO ratingDAO, IRatingListItemService ratingListItemService) {
        this.ratingDAO = ratingDAO;
        this.ratingListItemService = ratingListItemService;
    }

    @Override
    @Transactional(readOnly = true)
    public List<Rating> getAll() {
        return ratingDAO.getAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Rating getById(Long id) {
        return ratingDAO.getById(id);
    }

    @Override
    @Transactional
    public void create(Rating rating) {
        ratingDAO.create(rating);
    }

    @Override
    @Transactional
    public void update(Rating rating) {
        ratingDAO.update(rating);
    }

    @Override
    @Transactional
    public void delete(Rating rating) {
        ratingDAO.delete(rating);
    }

    /**
     * Updates user rating by summing all ratingListItems connected to that user
     * excluding those with rating value == 0
     *
     * @param userId user ID
     */
    @Override
    @Transactional
    public void updateUserRating(Long userId) {
        Rating rating = ratingDAO.getRatingByUserId(userId);
        List<RatingListItem> ratingListItems = ratingListItemService.getRatingListByRatedUser(userId);
        Double ratingValue = 0.0;
        Long numberOfVotes = (long) ratingListItems.size();
        for (RatingListItem ratingListItem : ratingListItems) {
            if (ratingListItem.getRatingValue() == 0.0) {
                numberOfVotes--;

            }
            ratingValue += ratingListItem.getRatingValue();
        }

        ratingValue = ratingValue / numberOfVotes;
        rating.setRating(ratingValue);
        ratingDAO.update(rating);

    }

    @Override
    @Transactional
    public Rating getRatingByUserId(Long userId) {
        return ratingDAO.getRatingByUserId(userId);
    }


    /**
     * Adds users that are tied to address inspector visited
     * so that they can rate inspector and vise versa
     * create user ratings in rating table
     *
     * @param inspector inspector that visited certain address
     * @param users     users that are bounded to that address
     */
    @Override
    @Transactional
    public void initialiseUsersRatings(User inspector, Set<User> users) {
        if (getRatingByUserId(inspector.getId()) == null) {
            create(new Rating(inspector));
        }

        for (User user : users) {
            List<RatingListItem> inspectorRatingHistory = ratingListItemService.getRatingListByRater(inspector.getId());
            List<RatingListItem> userRatingHistory = ratingListItemService.getRatingListByRater(user.getId());
            if (getRatingByUserId(user.getId()) == null) {
                create(new Rating(user));
            }
            if (!ratingListItemService.containsRatedUser(userRatingHistory, inspector)) {
                if (!user.getId().equals(inspector.getId())) {
                    ratingListItemService.create(new RatingListItem(user, inspector));
                }
            }
            if (!ratingListItemService.containsRatedUser(inspectorRatingHistory, user)) {
                if (!user.getId().equals(inspector.getId())) {
                    ratingListItemService.create(new RatingListItem(inspector, user));
                }
            }
        }
    }
}
