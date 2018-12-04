package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IRatingListItemDAO;
import com.softserveinc.ch067.easypay.model.RatingListItem;
import org.hibernate.HibernateException;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;
@Repository
public class RatingListItemDAOImpl extends PaginationDAO<RatingListItem> implements IRatingListItemDAO {

    @Override
    public List<RatingListItem> getRatingListByRater(Long raterId) throws HibernateException {
        return entityManager.createQuery("SELECT rl FROM RatingListItem rl WHERE rl.rater.id=:raterId ORDER BY rl.ratedUser.name, rl.ratedUser.surname", RatingListItem.class)
                .setParameter("raterId", raterId)
                .getResultList();
    }

    @Override
    public List<RatingListItem> getRatingListByRatedUser(Long ratedUserId) {
        return entityManager.createQuery("SELECT rl FROM RatingListItem rl WHERE rl.ratedUser.id=:ratedUserId", RatingListItem.class)
                .setParameter("ratedUserId", ratedUserId)
                .getResultList();
    }

    @Override
    public RatingListItem getItemByRaterAndRatedUserId(Long raterId, Long ratedUserId) {
        return entityManager.createQuery("SELECT rl FROM RatingListItem rl WHERE rl.ratedUser.id=:ratedUserId AND rl.rater.id=:raterId", RatingListItem.class)
                .setParameter("ratedUserId", ratedUserId)
                .setParameter("raterId", raterId)
                .getSingleResult();
    }

}
