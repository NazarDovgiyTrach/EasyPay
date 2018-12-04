package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IAddressDAO;
import com.softserveinc.ch067.easypay.model.*;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.Query;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;

@Repository
public class AddressDAOImpl extends CrudDAO<Address> implements IAddressDAO {

    @Override
    public boolean isUniqueness(Address address) {
        return !getAddressRegion(address.getRegion())
                || !getAddressCity(address.getCity())
                || !getAddressStreet(address.getStreet())
                || !getAddressHouse(address.getHouse())
                || !getAddressFlat(address.getFlat());
    }

    private boolean getAddressFlat(Flat flat) {
        Query query = entityManager.createQuery("select a.flat from Address a where a.flat.number = :number ", Flat.class);
        query.setParameter("number", flat.getNumber());
        return !query.getResultList().isEmpty();
    }

    private boolean getAddressHouse(House house) {
        Query query = entityManager.createQuery("select a.house from Address a where a.house.number = :number ", House.class);
        query.setParameter("number", house.getNumber());
        return !query.getResultList().isEmpty();
    }

    private boolean getAddressStreet(Street street) {
        Query query = entityManager.createQuery("select a.street from Address a where a.street.name = :name ", Street.class);
        query.setParameter("name", street.getName());
        return !query.getResultList().isEmpty();
    }

    private boolean getAddressCity(City city) {
        Query query = entityManager.createQuery("select a.city from Address a where a.city.name = :name ", City.class);
        query.setParameter("name", city.getName());
        return !query.getResultList().isEmpty();
    }

    private boolean getAddressRegion(Region region) {
        Query query = entityManager.createQuery("select a.region from Address a where a.region.name = :name ", Region.class);
        query.setParameter("name", region.getName());
        return !query.getResultList().isEmpty();
    }


    public Address getAddress(Region region, City city, Street street, House house, Flat flat) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Address> query = builder.createQuery(Address.class);
        Root<Address> root = query.from(Address.class);
        query.select(root).where(builder.equal(root.get("region"), region),
                builder.equal(root.get("city"), city),
                builder.equal(root.get("street"), street),
                builder.equal(root.get("house"), house),
                builder.equal(root.get("flat"), flat));
        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    @Transactional
    public void create(Address address) {
        entityManager.persist(address);
    }

    @Override
    public void update(Address address) {
        entityManager.merge(address);
    }

    @Override
    public void delete(Address address) {
        entityManager.remove(address);
    }

}
