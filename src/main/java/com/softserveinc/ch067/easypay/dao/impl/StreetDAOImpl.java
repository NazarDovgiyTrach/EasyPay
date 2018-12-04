package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IStreetDAO;
import com.softserveinc.ch067.easypay.model.Street;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.HashSet;
import java.util.Set;

@Repository
public class StreetDAOImpl extends CrudDAO<Street> implements IStreetDAO {

    @Override
    public Set<Street> getAllNames() {
        return new HashSet<>(entityManager.createQuery("select s from Street s", Street.class).getResultList());
    }

    @Override
    public boolean isUniqueness(String name, Long cityId) {
        Query query = entityManager.createQuery("select s.name from Street s where s.name = :name and s.city.id = :cityId");
        query.setParameter("name", name);
        query.setParameter("cityId", cityId);
        return query.getResultList().isEmpty();
    }

    @Override
    public Street getByNameAndCityId(String name, Long cityId) {
        Query query = entityManager.createQuery("select s from Street s where s.name = :name and s.city.id = :cityId");
        query.setParameter("name", name);
        query.setParameter("cityId", cityId);
        return (Street) query.getSingleResult();
    }
}
