package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IRatingListItemDAO;
import com.softserveinc.ch067.easypay.dto.UserRatingDTO;
import com.softserveinc.ch067.easypay.model.RatingListItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IRatingListItemService;
import com.softserveinc.ch067.easypay.service.IRatingService;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.NoResultException;
import java.util.ArrayList;
import java.util.List;

@Service
public class RatingListServiceImpl implements IRatingListItemService {

    private final static int MAX_RESULTS = 10;

    private final IRatingListItemDAO ratingListItemDAO;
    private final IUserService userService;

    @Autowired
    public RatingListServiceImpl(IRatingListItemDAO ratingListItemDAO,@Lazy IUserService userService) {
        this.ratingListItemDAO = ratingListItemDAO;
        this.userService = userService;
    }




    @Override
    @Transactional(readOnly = true)
    public List<RatingListItem> getAll() {
        return ratingListItemDAO.getAll();
    }

    @Override
    @Transactional(readOnly = true)
    public RatingListItem getById(Long id) {
        return ratingListItemDAO.getById(id);
    }

    @Override
    @Transactional
    public void create(RatingListItem ratingListItem) {
        ratingListItemDAO.create(ratingListItem);
    }

    @Override
    @Transactional
    public void update(RatingListItem ratingListItem) {

        ratingListItemDAO.update(ratingListItem);
    }

    @Override
    @Transactional
    public void delete(RatingListItem ratingListItem) {
        ratingListItemDAO.delete(ratingListItem);
    }

     /**
     * Gets userRatingDTOs by rater
     * @param raterId rater
     * @return rated use  r info and rating value
     */
    @Override
    @Transactional
    public List<UserRatingDTO> getUsersToRate(int pageId, Long raterId) {
        int firstResult = (pageId - 1) * MAX_RESULTS;
        List<RatingListItem> ratingListItems = getRatingListByRater(firstResult, raterId);
        List<UserRatingDTO> userRatingDTOS = new ArrayList<>();
        for (RatingListItem ratingListItem : ratingListItems) {
            userRatingDTOS.add(userService.constructUserRatingDTO(ratingListItem));
        }
        return userRatingDTOS;
    }

    @Override
    @Transactional
    public void updateUserRating(User rater, Long ratedUserId, Double ratingValue) {
        RatingListItem ratingListItem = ratingListItemDAO.getItemByRaterAndRatedUserId(rater.getId(), ratedUserId);
        ratingListItem.setRatingValue(ratingValue);
        ratingListItemDAO.update(ratingListItem);
    }

    @Override
    @Transactional(readOnly = true)
    public Long getPages(String extendSQL) {
        return ratingListItemDAO.getPages(extendSQL);
    }

    @Override
    @Transactional(readOnly = true)
    public List<RatingListItem> getObjects(int firstResult, String extendSQL) {
        return ratingListItemDAO.getObjects(firstResult, extendSQL);
    }

    @Override
    public Long getPagesRater(Long raterId) {
        String extendSQL = " WHERE t.rater.id=" + raterId + " GROUP BY t.rater.id";
        try {
            return ratingListItemDAO.getPages(extendSQL);
        } catch (NoResultException e) {
            return 1L;
        }
    }

    @Override
    public Long getPagesRated(Long ratedUserId) {
        String extendSQL = " WHERE t.ratedUser.id=" + ratedUserId + " GROUP BY t.ratedUser.id";
        try {
            return ratingListItemDAO.getPages(extendSQL);
        } catch (NoResultException e) {
            return 1L;
        }
    }


    @Override
    public boolean containsRatedUser(final List<RatingListItem> list, final User user) {
        return list.stream().anyMatch(o -> o.getRatedUser().equals(user));
    }

    @Override
    public boolean containsRater(final List<RatingListItem> list, final User user) {
        return list.stream().anyMatch(o -> o.getRater().equals(user));
    }

    @Override
    public List<RatingListItem> getRatingListByRater(int firstResult, Long raterId) {
        String extendSQL = " WHERE t.rater.id=" + raterId + " ORDER BY t.ratedUser.name, t.ratedUser.surname";
        return getObjects(firstResult, extendSQL);
    }

    @Override
    public List<RatingListItem> getRatingListByRatedUser(int firstResult, Long ratedUserId) {
        String extendSQL = " WHERE t.ratedUser.id=" + ratedUserId + " ORDER BY t.rater.name, t.rater.surname";
        return getObjects(firstResult, extendSQL);
    }

    @Override
    @Transactional(readOnly = true)
    public List<RatingListItem> getRatingListByRatedUser(Long ratedUserId) {
        return ratingListItemDAO.getRatingListByRatedUser(ratedUserId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<RatingListItem> getRatingListByRater(Long raterId) {
        return ratingListItemDAO.getRatingListByRater(raterId);
    }


}


