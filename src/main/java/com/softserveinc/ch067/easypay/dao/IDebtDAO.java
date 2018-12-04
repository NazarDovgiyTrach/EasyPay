package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.model.Debt;

import java.time.LocalDate;
import java.util.List;

public interface IDebtDAO extends IModel<Debt> {
    Debt getDebtByUtilityAndAddress(Long utilityId, Long addressId);

    List<DebtInfoForMailingDTO> getUnpaid(LocalDate beforeLastPaid,LocalDate beforeLastDeptReminderSend,int maxResult);

    List<DebtInfoForMailingDTO> getDebtWithUnreportedCounters(LocalDate beforeDate, LocalDate beforeLastCounterReminderSend,
                                                              int maxResults);
    void updateLastCounterReminderSend(List<Long> list);

    void updateLastDebtReminderSend(List<Long> list);

}
