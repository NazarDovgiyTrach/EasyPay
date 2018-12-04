package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import com.softserveinc.ch067.easypay.model.PaymentsHistory;
import com.softserveinc.ch067.easypay.util.PaymentsHistoryPDFDetails;

import java.util.List;

public interface IPaymentsHistoryService {
    List<PaymentsHistory> getAll();
    List<PaymentsHistory> getAllByUserId(Long id);
    PaymentsHistory getById(Long id);
    void create(PaymentsHistory paymentsHistory);
    List<PaymentsHistory> getAllByAddressAndUtility(Long addressId, Long utilityId);
    GeneratedFileDTO generateCheck(PaymentsHistoryPDFDetails details, PaymentsHistory history) throws Exception;
    void update(PaymentsHistory paymentsHistory);
    List<PaymentsHistory> getLimitedByAddressAndUtility(Long addressId, Long utilityId, int pageId);
    Long getPages(Long addressId, Long utilityId);
}
