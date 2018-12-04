package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.ScheduleItemHistory;
import com.softserveinc.ch067.easypay.model.User;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.List;

public interface IScheduleHistoryDAO extends IModel<ScheduleItemHistory> {
    List<ScheduleItemHistory> getAllSHItemsByInspectorId(long userId);
    List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(long userId);
    List<ScheduleItemHistory> getPastSHItemsByInspectorId(long userId, String earlier);
    List<ScheduleItemHistory> getObjects(int firstResult, String extendSQL);
    Long getPages(String extendSQL);
}
