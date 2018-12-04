package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IHouseDAO;
import com.softserveinc.ch067.easypay.model.House;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.HashSet;
import java.util.Set;

@Repository
public class HouseDAOImpl extends CrudDAO<House> implements IHouseDAO {

    @Override
    public Set<House> getAllNumbers() {
        return new HashSet<>(entityManager.createQuery("select h from House h", House.class).getResultList());
    }

    @Override
    public boolean isUniqueness(String number, Long streetId) {
        Query query = entityManager.createQuery("select h.number from House h where h.number = :number and h.street.id = :streetId");
        query.setParameter("number", number);
        query.setParameter("streetId", streetId);
        return query.getResultList().isEmpty();
    }

    @Override
    public House getByNumberAndStreetId(String number, Long streetId) {
        Query query = entityManager.createQuery("select h from House h where h.number = :number and h.street.id = :streetId");
        query.setParameter("number", number);
        query.setParameter("streetId", streetId);
        return (House) query.getSingleResult();
    }
}
