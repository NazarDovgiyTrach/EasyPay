package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.dto.InfoForCheckDTO;
import com.softserveinc.ch067.easypay.model.Debt;
import com.softserveinc.ch067.easypay.model.User;

import java.time.LocalDate;
import java.util.List;

public interface IDebtService {
    Debt getDebtByUtilityAndAddress(Long utilityId, Long addressId);

    List<Debt> getAll();

    Debt getById(Long id);

    void create(Debt debt);

    void update(Debt debt);

    void delete(Debt debt);

    InfoForCheckDTO payForUtility(double sum, Long addressId, Long utilityId, User user);

    List<DebtInfoForMailingDTO> getUnpaid(LocalDate beforeLastPaid,LocalDate beforeLastDeptReminderSend,int maxResult);

    void checkFixedCounters(int maxResults);

    List<DebtInfoForMailingDTO> getDebtWithUnreportedCounters(LocalDate beforeDate, LocalDate beforeLastCounterReminderSend,
                                                              int maxResults);

    void updateLastCounterReminderSend(List<Long> list);

    void updateLastDebtReminderSend(List<Long> list);

}
