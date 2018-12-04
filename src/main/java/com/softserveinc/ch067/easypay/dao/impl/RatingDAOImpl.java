package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IRatingDAO;
import com.softserveinc.ch067.easypay.model.Rating;
import org.hibernate.HibernateException;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;
@Repository
public class RatingDAOImpl extends PaginationDAO<Rating> implements IRatingDAO {

    @Override
    public Rating getRatingByUserId(Long userId) throws HibernateException {
        List<Rating> ratings = entityManager.createQuery("SELECT r FROM Rating r WHERE r.user.id=:userId", Rating.class)
                .setParameter("userId", userId)
                .getResultList();
        if (ratings.isEmpty())
            return null;
        else
            return ratings.get(0);
    }


}
