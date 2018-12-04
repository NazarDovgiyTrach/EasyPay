package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.ICurrentPriceDAO;
import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.Utility;
import org.springframework.stereotype.Repository;

import javax.persistence.NoResultException;
import javax.persistence.Query;

import java.time.LocalDate;
import java.util.List;

@Repository
public class CurrentPriceDAOImpl extends CrudDAO<CurrentPrice> implements ICurrentPriceDAO {

    @Override
    public CurrentPrice getCurrentPriceByUtility(Utility utility) {
        Query query = entityManager.createQuery("SELECT cp FROM CurrentPrice cp WHERE cp.utility.id = :utilityId AND cp.active = true", CurrentPrice.class);
        query.setParameter("utilityId", utility.getId());
        return (CurrentPrice) query.getSingleResult();
    }

    @Override
    public CurrentPrice getCurrentPriceForUtilityByUserId(Long userId) {
        Query query = entityManager.createQuery("SELECT cp FROM CurrentPrice cp join fetch cp.utility u join fetch u.address a WHERE cp.utility.manager.id = :userId AND cp.active = :active", CurrentPrice.class);
        query.setParameter("userId", userId);
        query.setParameter("active", true);

        try {
            return (CurrentPrice) query.getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    @Override
    public List<CurrentPrice> getPriceHistoryByUtilityId(Long utilityId, LocalDate startDate, LocalDate targetDate) {
        Query query = entityManager.createQuery("SELECT cp FROM CurrentPrice cp WHERE cp.utility.id = :utilityId AND " +
                "cp.date BETWEEN :startDate AND :targetDate", CurrentPrice.class);
        query.setParameter("utilityId", utilityId);
        query.setParameter("startDate", startDate);
        query.setParameter("targetDate", targetDate);

        return query.getResultList();
    }

    @Override
    public void disableCurrentPrice(Long utilityId) {
        Query query = entityManager.createQuery("UPDATE CurrentPrice cp SET cp.active = :active WHERE cp.active = :currentActive AND cp.utility.id = :utilityId");
        query.setParameter("active", false);
        query.setParameter("currentActive", true);
        query.setParameter("utilityId", utilityId);

        query.executeUpdate();
    }
}
