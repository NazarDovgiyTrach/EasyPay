package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.ICityDAO;
import com.softserveinc.ch067.easypay.model.City;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Repository
public class CityDAOImpl extends CrudDAO<City> implements ICityDAO {

    @Override
    public Set<City> getAllNames() {
        return new HashSet<>(entityManager.createQuery("select c from City c where c.id = :id", City.class).getResultList());
    }

    @Override
    public boolean cityUniqueness(String name) {
        Query query = entityManager.createQuery("select c.name from City c where c.name = :name");
        query.setParameter("name", name);
        return query.getResultList().isEmpty();
    }

    @Override
    public City getByName(String name) {
        Query query = entityManager.createQuery("select c from City c where c.name = :name", City.class);
        query.setParameter("name", name);
        return (City) query.getSingleResult();
    }
}
