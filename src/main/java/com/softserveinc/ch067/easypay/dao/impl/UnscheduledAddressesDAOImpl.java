package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IUnscheduledAddressesDAO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.UnscheduledAddresses;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityGraph;
import java.util.List;

@Repository
public class UnscheduledAddressesDAOImpl extends PaginationDAO<UnscheduledAddresses> implements IUnscheduledAddressesDAO {

    @Override
    public List<UnscheduledAddresses> getByUtilityId(Long utilityId, EntityGraphType type, String... attributeGraph) {
        EntityGraph<UnscheduledAddresses> entityGraph = entityManager.createEntityGraph(UnscheduledAddresses.class);
        buildEntityGraph(entityGraph, attributeGraph);

        return entityManager.createNamedQuery("UnscheduledAddresses.getByUtilityId", UnscheduledAddresses.class)
                .setHint(type.getType(), entityGraph)
                .setParameter("utilityId", utilityId)
                .getResultList();
    }

    @Override
    public List<Address> getAddressListByUtilityId(Long utilityId) {
        return entityManager.createNamedQuery("UnscheduledAddresses.getAddressByUtilityId", Address.class)
                .setParameter("utilityId", utilityId)
                .getResultList();
    }

    @Override
    public List<Address> getObjects(Long utilityId, int firstResult) {
        return entityManager.createNamedQuery("UnscheduledAddresses.getAddressByUtilityId", Address.class)
                .setParameter("utilityId", utilityId)
                .setFirstResult(firstResult)
                .setMaxResults(10)
                .getResultList();
    }

    @Override
    public Long getPages(Long utilityId) {
        Long count = entityManager.createNamedQuery("UnscheduledAddresses.getPageSize", Long.class)
                .setParameter("utilityId", utilityId)
                .getSingleResult();
        return (long) Math.ceil((double) count / 10);
    }

}
