package com.softserveinc.ch067.easypay.cron;

import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.ScheduleItemHistory;
import com.softserveinc.ch067.easypay.model.Status;
import com.softserveinc.ch067.easypay.service.IScheduleHistoryService;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.ArrayList;

@Component
@EnableScheduling
public class ScheduleCron {

    private final IScheduleService scheduleService;
    private final IScheduleHistoryService scheduleHistoryService;

    @Autowired
    public ScheduleCron(IScheduleService scheduleService, IScheduleHistoryService scheduleHistoryService) {
        this.scheduleService = scheduleService;
        this.scheduleHistoryService = scheduleHistoryService;
    }

    @Scheduled(fixedRate = 36000000)
    public void setOverdueStatusToScheduleItems() {
        ArrayList<ScheduleItem> overdue = (ArrayList<ScheduleItem>) scheduleService.getOverdueItems();

        for (ScheduleItem scheduleItem : overdue) {
            ScheduleItemHistory scheduleItemHistory = new ScheduleItemHistory();
            scheduleItemHistory.setInspector(scheduleItem.getInspector());
            scheduleItemHistory.setAddress(scheduleItem.getAddress());
            scheduleItemHistory.setEventDate(scheduleItem.getEventDate());
            scheduleItemHistory.setSubmitDate(LocalDate.now());
            scheduleItemHistory.setStatus(Status.OVERDUE);
            scheduleItemHistory.setComment("Overdue visit");
            scheduleHistoryService.create(scheduleItemHistory);

            if (scheduleItem.getRepeat()) {
                scheduleItem.setEventDate(scheduleItem.getEventDate().withMonth(LocalDate.now().plusMonths(1).getMonthValue()));
                scheduleService.update(scheduleItem);
            } else {
                scheduleService.delete(scheduleItem);
            }
        }
    }

}
