package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.ScheduleItemHistory;

import java.sql.Timestamp;
import java.util.List;

public interface IScheduleHistoryService {
    List<ScheduleItemHistory> getAll();

    List<ScheduleItemHistory> getSHItemsByInspectorId(long userId);

    ScheduleItemHistory getById(Long id);

    void create(ScheduleItemHistory scheduleItemHistory);

    void update(ScheduleItemHistory scheduleItemHistory);

    void delete(ScheduleItemHistory scheduleItemHistory);

    List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(long userId);

    List<ScheduleItemHistory> getPastSHItemsByInspectorId(long userId);

    List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(long userId, int firstResult);

    List<ScheduleItemHistory> getPastSHItemsByInspectorId(long userId, int firstResult);

    Long getSHCurrentPages(long userId);

    Long getSHPastPages(long userId);
}
