package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.annotation.Loggable;
import com.softserveinc.ch067.easypay.dao.IDebtDAO;
import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.dto.InfoForCheckDTO;
import com.softserveinc.ch067.easypay.dto.CounterDTO;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.*;
import com.softserveinc.ch067.easypay.util.PaymentsHistoryPDFDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class DebtServiceImpl implements IDebtService {

    private final String resourceHandlerFilesDir;


    private final IDebtDAO debtDAO;


    private final IUtilityService utilityService;


    private final ICurrentPriceService currentPriceService;


    private final IUserService userService;


    private final IAddressService addressService;


    private final ICounterService counterService;


    private final IPaymentsHistoryService paymentsHistoryService;

    @Autowired
    public DebtServiceImpl(@Qualifier("resourceHandlerFilesDir") String resourceHandlerFilesDir,
                           IDebtDAO debtDAO,
                           @Lazy IUtilityService utilityService,
                           ICurrentPriceService currentPriceService,
                           IUserService userService,
                           IAddressService addressService,
                           @Lazy ICounterService counterService,
                           IPaymentsHistoryService paymentsHistoryService) {
        this.resourceHandlerFilesDir = resourceHandlerFilesDir;
        this.debtDAO = debtDAO;
        this.utilityService = utilityService;
        this.currentPriceService = currentPriceService;
        this.userService = userService;
        this.addressService = addressService;
        this.counterService = counterService;
        this.paymentsHistoryService = paymentsHistoryService;
    }

    @Override
    public Debt getDebtByUtilityAndAddress(Long utilityId, Long addressId) {
        return debtDAO.getDebtByUtilityAndAddress(utilityId, addressId);
    }

    @Override
    public List<Debt> getAll() {
        return debtDAO.getAll();
    }

    @Override
    public Debt getById(Long id) {
        return debtDAO.getById(id);
    }

    @Transactional
    @Override
    public void create(Debt debt) {
        debtDAO.create(debt);
    }

    @Transactional
    @Override
    public void update(Debt debt) {
        debtDAO.update(debt);
    }

    @Override
    public void delete(Debt debt) {
        debtDAO.delete(debt);
    }

    @Transactional
    @Override
    public InfoForCheckDTO payForUtility(double sum, Long addressId, Long utilityId, User user) {
        PaymentsHistoryPDFDetails details = new PaymentsHistoryPDFDetails();

        details.setPaymentTime(Timestamp.from(Instant.now()));

        Debt debt = getDebtByUtilityAndAddress(utilityId, addressId);
        details.setOldDebt(debt.getValue());

        debt.setValue(debt.getValue() - sum);
        debt.setLastPaid(LocalDate.now());

        details.setNewDebt(debt.getValue());
        update(debt);

        Utility utility = utilityService.getById(utilityId);
        details.setServiceName(utility.getName());
        details.setUserName(user.getName() + " " + user.getSurname());

        Set<Counter> counters = userService.getCountersByConnectedUtilityAndAddress(utility, addressId, user.getId());
        Set<CounterDTO> countersForDetails = new HashSet<>();

        for (Counter counter : counters)
            countersForDetails.add(new CounterDTO(counter.getId(), counter.getUser().getId(), counter.getAddress().getId(),
                                                 counter.getOldValue(), counter.getCurrentValue(), counter.isActive(), counter.isFixed()));

        CurrentPrice price = currentPriceService.getCurrentPriceByUtility(utility);
        Address address = addressService.getById(addressId);

        details.setRate(price.getPrice());
        details.setAddress(address.getFullAddressString());
        details.setCounters(countersForDetails);
        details.setUserEmail(user.getEmail());

        for (Counter counter : counters){
            if (!counter.getOldValue().equals(counter.getCurrentValue())) {
                if (!counter.isFixed())
                    counter.setOldValue(counter.getCurrentValue());
                counterService.update(counter);
            }
        }


        PaymentsHistory paymentsHistory = new PaymentsHistory();
        String fileName = (utility.getName() + details.getPaymentTime()).replaceAll(":", "") + ".pdf";
        paymentsHistory.setCheckPath(resourceHandlerFilesDir + "checks/" + user.getEmail() + "/" + fileName);
        paymentsHistory.setUtility(utility);
        paymentsHistory.setPaymentSum(sum);
        paymentsHistory.setAddress(address);
        paymentsHistory.setPayDate(LocalDate.now());

        paymentsHistoryService.create(paymentsHistory);

        details.setFileName(fileName);

        return new InfoForCheckDTO(details, paymentsHistory);
    }


    @Override
    public List<DebtInfoForMailingDTO> getUnpaid(LocalDate beforeLastPaid,LocalDate beforeLastDeptReminderSend,int maxResult) {
        return debtDAO.getUnpaid(beforeLastPaid, beforeLastDeptReminderSend,maxResult);
    }

    @Override
    public List<DebtInfoForMailingDTO> getDebtWithUnreportedCounters(LocalDate beforeDate, LocalDate beforeLastCounterReminderSend, int maxResults) {
        return debtDAO.getDebtWithUnreportedCounters(beforeDate, beforeLastCounterReminderSend, maxResults);
    }

    @Override
    @Transactional
    public void checkFixedCounters(int maxResults){
        LocalDate firstDay = LocalDate.now().withDayOfMonth(1);
        List<Counter> counters = counterService.getFixedCounterForRegularPay(firstDay,maxResults);
        CurrentPrice currentPrice;
        Debt debt;
        for (Counter counter:counters){
            debt = counter.getDebt();
            currentPrice = currentPriceService.getCurrentPriceByUtility(debt.getUtility());
            debt.setValue(debt.getValue() + currentPrice.getPrice());
            counter.setLastUpdated(LocalDate.now());
            counterService.update(counter);
            if (debt.getValue() <= 0){
                debt.setLastPaid(LocalDate.now());
            }
            debtDAO.update(debt);
        }
    }

    @Override
    @Transactional
    public void updateLastCounterReminderSend(List<Long> list) {
        debtDAO.updateLastCounterReminderSend(list);
    }

    @Override
    @Transactional
    public void updateLastDebtReminderSend(List<Long> list) {
        debtDAO.updateLastDebtReminderSend(list);
    }
}
