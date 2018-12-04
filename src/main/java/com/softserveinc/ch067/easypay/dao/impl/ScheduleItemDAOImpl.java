package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IScheduleItemDAO;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityGraph;
import java.time.LocalDate;
import java.util.List;

@Repository
public class ScheduleItemDAOImpl extends PaginationDAO<ScheduleItem> implements IScheduleItemDAO {

    @Override
    public ScheduleItem getById(Long id, EntityGraphType type, String... attributeGraph) {
        EntityGraph<ScheduleItem> entityGraph = entityManager.createEntityGraph(ScheduleItem.class);
        buildEntityGraph(entityGraph, attributeGraph);

        List<ScheduleItem> scheduleItems = entityManager.createNamedQuery("ScheduleItem.getById", ScheduleItem.class)
                .setHint(type.getType(), entityGraph)
                .setParameter("id", id)
                .getResultList();

        return scheduleItems.isEmpty() ? null : scheduleItems.get(0);
    }

    @Override
    public List<ScheduleItem> getListByUserId(Long id, EntityGraphType type, String... attributeGraph) {
        EntityGraph<ScheduleItem> entityGraph = entityManager.createEntityGraph(ScheduleItem.class);
        buildEntityGraph(entityGraph, attributeGraph);

        return entityManager.createNamedQuery("ScheduleItem.getByInspectorId", ScheduleItem.class)
                .setHint(type.getType(), entityGraph)
                .setParameter("inspectorId", id)
                .getResultList();
    }

    @Override
    public List<ScheduleItem> getOverdueItems() {
        EntityGraph<ScheduleItem> entityGraph = entityManager.createEntityGraph(ScheduleItem.class);
        buildEntityGraph(entityGraph, new String[]{"inspector", "address"});

        return entityManager.createNamedQuery("ScheduleItem.getOverdueItems", ScheduleItem.class)
                .setHint(EntityGraphType.LOAD.getType(), entityGraph)
                .getResultList();
    }

    @Override
    public boolean isExist(Long addressId, List<Long> inspectorsId) {
        Long count = entityManager.createNamedQuery("ScheduleItem.getCountByAddressAndInspectorId", Long.class)
                .setParameter("id", addressId)
                .setParameter("inspectors_id", inspectorsId)
                .getSingleResult();

        return count > 0;
    }

    @Override
    public Long getCountItemsByUserIdAndDate(Long id, LocalDate date) {
        return entityManager.createNamedQuery("ScheduleItem.getCountItemsByUserIdAndDate", Long.class)
                .setParameter("id", id)
                .setParameter("date", date)
                .getSingleResult();
    }

}
