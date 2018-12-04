package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IPaymentsHistoryDAO;
import com.softserveinc.ch067.easypay.model.PaymentsHistory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class PaymentsHistoryDAOImpl extends PaginationDAO<PaymentsHistory> implements IPaymentsHistoryDAO {

    @Override
    public List<PaymentsHistory> getAllByUserId(Long id) {
        return entityManager.createQuery("SELECT h FROM PaymentsHistory h WHERE h.user.id = :id", PaymentsHistory.class).setParameter("id", id).getResultList();
    }

    @Override
    public List<PaymentsHistory> getAllByAddressAndUtility(Long addressId, Long utilityId) {
        return entityManager.createQuery("SELECT h FROM PaymentsHistory h WHERE h.address.id = :addressId AND h.utility.id = :utilityId", PaymentsHistory.class)
                .setParameter("addressId", addressId)
                .setParameter("utilityId", utilityId)
                .getResultList();
    }
}
