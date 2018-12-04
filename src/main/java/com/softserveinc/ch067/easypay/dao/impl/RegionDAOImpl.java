package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IRegionDAO;
import com.softserveinc.ch067.easypay.model.Region;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.HashSet;
import java.util.Set;

@Repository
public class RegionDAOImpl extends CrudDAO<Region> implements IRegionDAO {

    @Override
    public Set<Region> getAllNames() {
        return new HashSet<>(entityManager.createQuery("select r from Region r", Region.class).getResultList());
    }

    @Override
    public boolean regionUniqueness(String name) {
        Query query = entityManager.createQuery("SELECT r.name from Region r where r.name = :name", String.class);
        query.setParameter("name", name);
        return query.getResultList().isEmpty();
    }

    @Override
    public Region getByName(String name) {

        Query query = entityManager.createQuery("SELECT r from Region r where r.name = :name", Region.class);
        query.setParameter("name", name);

         return (Region) query.getSingleResult();
    }
}
