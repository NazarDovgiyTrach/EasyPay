package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IFlatDAO;
import com.softserveinc.ch067.easypay.model.Flat;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.HashSet;
import java.util.Set;

@Repository
public class FlatDAOImpl extends CrudDAO<Flat> implements IFlatDAO {

    @Override
    public Set<Flat> getAllNumbers() {
        return new HashSet<>(entityManager.createQuery("select f from Flat f", Flat.class).getResultList());
    }

    @Override
    public boolean isUniqueness(String number, Long houseId) {
        Query query = entityManager.createQuery("select f from Flat f where f.number = :number and f.house.id = :houseId");
        query.setParameter("number", number);
        query.setParameter("houseId", houseId);
        return query.getResultList().isEmpty();
    }

    @Override
    public Flat getByNumberAndHouseId(String number, Long houseId) {
        Query query = entityManager.createQuery("select f from Flat f where f.number = :number and f.house.id = :houseId");
        query.setParameter("number", number);
        query.setParameter("houseId", houseId);
        return (Flat) query.getSingleResult();
    }
}
