package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.ScheduleItem;

import java.time.LocalDate;
import java.util.List;

public interface IScheduleItemDAO extends IModel<ScheduleItem> {

    ScheduleItem getById(Long id, EntityGraphType type, String... attributeGraph);

    List<ScheduleItem> getListByUserId(Long id, EntityGraphType type, String... attributeGraph);

    List<ScheduleItem> getOverdueItems();

    Long getCountItemsByUserIdAndDate(Long id, LocalDate date);

    boolean isExist(Long addressId, List<Long> inspectorsId);
}
