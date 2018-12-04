package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.ICounterDAO;
import com.softserveinc.ch067.easypay.model.Counter;
import org.springframework.stereotype.Repository;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;

@Repository
public class CounterDAOImpl extends CrudDAO<Counter> implements ICounterDAO {

    @Override
    public List<Counter> getAllByUserId(Long id) {
        return entityManager.createQuery("SELECT c FROM Counter c WHERE c.user.id = :id", Counter.class)
                .setParameter("id", id).getResultList();
    }

    @Override
    public List<Counter> getCountersByAddressId(Long id) {
        return entityManager.createQuery("SELECT c FROM Counter c WHERE c.address.id = :id", Counter.class)
                .setParameter("id", id)
                .getResultList();
    }

    public List<Counter> getFixedCounterForRegularPay(LocalDate beforeDate, int maxResults){
        return entityManager.createNamedQuery("Counter.getFixedCounterForRegularPay")
                .setParameter("beforeDate",beforeDate)
                .setMaxResults(maxResults)
                .getResultList();
    }
}
