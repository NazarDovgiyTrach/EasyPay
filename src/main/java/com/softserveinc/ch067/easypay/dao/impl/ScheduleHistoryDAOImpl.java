package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IScheduleHistoryDAO;
import com.softserveinc.ch067.easypay.model.ScheduleItemHistory;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class ScheduleHistoryDAOImpl extends PaginationDAO<ScheduleItemHistory> implements IScheduleHistoryDAO {

    @Override
    public List<ScheduleItemHistory> getAllSHItemsByInspectorId(long userId) {
        return entityManager.createQuery("SELECT sh FROM ScheduleItemHistory sh WHERE sh.inspector.id=:userId", ScheduleItemHistory.class)
                .setParameter("userId", userId)
                .getResultList();
    }

    @Override
    public List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(long userId) {
        return entityManager.createQuery("SELECT sh FROM ScheduleItemHistory sh WHERE sh.inspector.id =:userId AND extract(month from sh.eventDate) = extract(month from CURRENT_DATE) ORDER BY sh.eventDate ASC", ScheduleItemHistory.class)
                .setParameter("userId", userId)
                .getResultList();
    }

    @Override
    public List<ScheduleItemHistory> getPastSHItemsByInspectorId(long userId, String earlier) {
        return entityManager.createQuery("SELECT sh FROM ScheduleItemHistory sh WHERE sh.inspector.id =:userId AND extract(month from sh.eventDate) = extract(month from to_timestamp(:earlier, 'dd-MM-YYYY')) ORDER BY sh.eventDate ASC", ScheduleItemHistory.class)
                .setParameter("userId", userId)
                .setParameter("earlier", earlier)
                .getResultList();
    }


}
