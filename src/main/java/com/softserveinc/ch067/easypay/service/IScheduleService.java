package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.List;

public interface IScheduleService {

    List<ScheduleItem> getAll();

    ScheduleItem getById(Long id, boolean withAddress, boolean withInspector);

    void create(ScheduleItem scheduleItem);

    void update(ScheduleItem scheduleItem);

    void delete(ScheduleItem scheduleItem);

    void delete(Long id);

    List<ScheduleItem> getListByUserId(Long id, boolean withAddress, boolean withInspector);

    List<ScheduleItem> getOverdueItems();
    
    boolean isExist(Address address, List<User> inspectors);

    LocalDate getLeastBusyDayOfInspector(User inspector);

    void addScheduleItemForCall(Utility utility, Timestamp date, Address address);

    User getInspectorForCall(List<User> inspectors, Timestamp date, Address address);

    void deleteAllItemsForInspector(Long idInspector);

}
