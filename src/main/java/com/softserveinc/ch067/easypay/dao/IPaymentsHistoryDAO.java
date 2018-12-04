package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.PaymentsHistory;

import java.util.List;

public interface IPaymentsHistoryDAO extends IModel<PaymentsHistory> {
    List<PaymentsHistory> getAll();
    List<PaymentsHistory> getAllByUserId(Long id);
    List<PaymentsHistory> getAllByAddressAndUtility(Long addressId, Long utilityId);
    List<PaymentsHistory> getObjects(int firstResult, String extendSQL);
    Long getPages(String extendSQL);
}
