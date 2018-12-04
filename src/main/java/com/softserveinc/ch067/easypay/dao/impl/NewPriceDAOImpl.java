package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.INewPriceDAO;
import com.softserveinc.ch067.easypay.model.NewPrice;
import org.springframework.stereotype.Repository;

import javax.persistence.NoResultException;
import javax.persistence.Query;

@Repository
public class NewPriceDAOImpl extends CrudDAO<NewPrice> implements INewPriceDAO {

    @Override
    public NewPrice getNewPriceByCurrentPriceId(Long currentPriceId) {
        Query query = entityManager.createQuery("SELECT np FROM NewPrice np WHERE np.currentPrice.currentPriceId = :currentPriceId", NewPrice.class);
        query.setParameter("currentPriceId", currentPriceId);
        try {
            return (NewPrice) query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    @Override
    public void updateCurrentPriceId(Long newCurrentPriceId, Long oldCurrentPriceId) {
        Query query = entityManager.createQuery("UPDATE NewPrice np SET np.currentPrice.currentPriceId = :newCurrentPriceId " +
                "WHERE np.currentPrice.currentPriceId = :currentPriceId");
        query.setParameter("newCurrentPriceId", newCurrentPriceId);
        query.setParameter("currentPriceId", oldCurrentPriceId);

        query.executeUpdate();
    }
}
