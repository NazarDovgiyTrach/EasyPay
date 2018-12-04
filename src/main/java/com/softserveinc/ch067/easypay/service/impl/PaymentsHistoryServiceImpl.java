package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IPaymentsHistoryDAO;
import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import com.softserveinc.ch067.easypay.model.PaymentsHistory;
import com.softserveinc.ch067.easypay.service.IPaymentsHistoryService;
import com.softserveinc.ch067.easypay.util.HistoryPDFBuilder;
import com.softserveinc.ch067.easypay.util.PaymentsHistoryPDFDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.NoResultException;
import java.util.List;

@Service
public class PaymentsHistoryServiceImpl implements IPaymentsHistoryService {
    private final IPaymentsHistoryDAO paymentsHistoryDAO;
    private final HistoryPDFBuilder historyPDFBuilder;

    @Autowired
    public PaymentsHistoryServiceImpl(IPaymentsHistoryDAO paymentsHistoryDAO, HistoryPDFBuilder historyPDFBuilder) {
        this.paymentsHistoryDAO = paymentsHistoryDAO;
        this.historyPDFBuilder = historyPDFBuilder;
    }

    private static final int MAX_RESULTS = 10;

    @Override
    public List<PaymentsHistory> getAll() {
        return paymentsHistoryDAO.getAll();
    }

    @Override
    public List<PaymentsHistory> getAllByUserId(Long id) {
        return paymentsHistoryDAO.getAllByUserId(id);
    }

    @Override
    public PaymentsHistory getById(Long id) {
        return paymentsHistoryDAO.getById(id);
    }

    @Override
    @Transactional
    public void create(PaymentsHistory paymentsHistory) {
        paymentsHistoryDAO.create(paymentsHistory);
    }

    @Override
    public List<PaymentsHistory> getAllByAddressAndUtility(Long addressId, Long utilityId) {
        return paymentsHistoryDAO.getAllByAddressAndUtility(addressId, utilityId);
    }

    @Transactional
    @Override
    public void update(PaymentsHistory paymentsHistory) {
        paymentsHistoryDAO.update(paymentsHistory);
    }

    @Transactional
    @Override
    public GeneratedFileDTO generateCheck(PaymentsHistoryPDFDetails details, PaymentsHistory paymentsHistory) throws Exception {
        GeneratedFileDTO fileInfo = historyPDFBuilder.createCheck(details, paymentsHistory);

        update(paymentsHistory);

        return fileInfo;
    }

    @Override
    public List<PaymentsHistory> getLimitedByAddressAndUtility(Long addressId, Long utilityId, int pageId) {
        int firstResult = (pageId - 1) * MAX_RESULTS;

        String extendSQL = " WHERE t.address.id = " + addressId + " AND t.utility.id = " + utilityId;

        return paymentsHistoryDAO.getObjects(firstResult, extendSQL);
    }

    @Override
    public Long getPages(Long addressId, Long utilityId) {
        String extendSQL = " WHERE t.address.id = " + addressId + " AND t.utility.id = " + utilityId;
        try {
            return paymentsHistoryDAO.getPages(extendSQL);
        }
        catch (NoResultException e){
            return 1L;
        }
    }
}
