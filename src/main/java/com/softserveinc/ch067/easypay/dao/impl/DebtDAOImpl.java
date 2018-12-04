package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IDebtDAO;

import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.model.Debt;
import org.springframework.stereotype.Repository;



import java.time.LocalDate;
import java.util.List;

@Repository
public class DebtDAOImpl extends CrudDAO<Debt> implements IDebtDAO {

    @Override
    public Debt getDebtByUtilityAndAddress(Long utilityId, Long addressId) {
        List<Debt> debts = entityManager.createNamedQuery("Debt.getDebtByUtilityAndAddress", Debt.class)
                .setParameter("utilityId", utilityId)
                .setParameter("addressId", addressId)
                .getResultList();
        return debts.isEmpty() ? null : debts.get(0);
    }


    @Override
    public List<DebtInfoForMailingDTO> getUnpaid(LocalDate beforeLastPaid, LocalDate beforeLastDeptReminderSend, int maxResult) {
        return entityManager.createNamedQuery("Debt.getUnpaid",DebtInfoForMailingDTO.class)
                .setParameter("beforeLastPaid",beforeLastPaid)
                .setParameter("lastDebtReminderSend",beforeLastDeptReminderSend)
                .setMaxResults(maxResult)
                .getResultList();
    }

    @Override
    public List<DebtInfoForMailingDTO> getDebtWithUnreportedCounters(LocalDate beforeDate, LocalDate beforeLastCounterReminderSend,
                                                    int maxResults){
        return entityManager.createNamedQuery("Debt.getDebtWithUnreportedCounters",DebtInfoForMailingDTO.class)
                .setParameter("beforeDate",beforeDate)
                .setParameter("lastReminderSend",beforeLastCounterReminderSend)
                .setMaxResults(maxResults)
                .getResultList();
    }

    @Override
    public void updateLastCounterReminderSend(List<Long> list) {
        entityManager.createNamedQuery("Debt.updateLastCounterReminderSend" )
                .setParameter("today",LocalDate.now())
                .setParameter("idList",list)
                .executeUpdate();
    }

    @Override
    public void updateLastDebtReminderSend(List<Long> list) {
        entityManager.createNamedQuery("Debt.updateLastDebtReminderSend" )
                .setParameter("today",LocalDate.now())
                .setParameter("idList",list)
                .executeUpdate();
    }
}
