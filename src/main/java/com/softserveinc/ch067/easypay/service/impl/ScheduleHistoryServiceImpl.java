package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IScheduleHistoryDAO;
import com.softserveinc.ch067.easypay.model.ScheduleItemHistory;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IRatingListItemService;
import com.softserveinc.ch067.easypay.service.IRatingService;
import com.softserveinc.ch067.easypay.service.IScheduleHistoryService;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.NoResultException;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAdjusters;
import java.util.List;
import java.util.Set;

@Service
public class ScheduleHistoryServiceImpl implements IScheduleHistoryService {

    private IScheduleHistoryDAO scheduleHistoryDAO;
    private IUserService userService;
    private IRatingService ratingService;

    @Autowired
    public ScheduleHistoryServiceImpl(IScheduleHistoryDAO scheduleHistoryDAO, IUserService userService, IRatingService ratingService) {
        this.scheduleHistoryDAO = scheduleHistoryDAO;
        this.userService = userService;
        this.ratingService = ratingService;
    }

    private final static int MAX_RESULTS = 10;

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItemHistory> getAll() {
        return scheduleHistoryDAO.getAll();
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItemHistory> getSHItemsByInspectorId(long userId) {
        return scheduleHistoryDAO.getAllSHItemsByInspectorId(userId);
    }

    @Override
    @Transactional(readOnly = true)
    public ScheduleItemHistory getById(Long id) {
        return scheduleHistoryDAO.getById(id);
    }

    @Override
    @Transactional
    public void create(ScheduleItemHistory scheduleItemHistory) {
        User inspector = scheduleItemHistory.getInspector();
        Set<User> users = userService.getUsersByAddress(scheduleItemHistory.getAddress());
        ratingService.initialiseUsersRatings(inspector, users);
        scheduleHistoryDAO.create(scheduleItemHistory);
    }

    @Override
    @Transactional
    public void update(ScheduleItemHistory scheduleItemHistory) {
        scheduleHistoryDAO.update(scheduleItemHistory);
    }

    @Override
    @Transactional
    public void delete(ScheduleItemHistory scheduleItemHistory) {
        scheduleHistoryDAO.delete(scheduleItemHistory);
    }

    @Override
    @Transactional
    public List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(long userId) {
        return scheduleHistoryDAO.getCurrentSHItemsByInspectorId(userId);
    }

    @Override
    @Transactional
    public List<ScheduleItemHistory> getPastSHItemsByInspectorId(long userId) {
        LocalDate now = LocalDate.now();
        LocalDate earlier = now.minusMonths(1);
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("dd-MM-YYYY");
        String dateString = dateTimeFormatter.format(earlier);
        return scheduleHistoryDAO.getPastSHItemsByInspectorId(userId, dateString);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(long userId, int pageId) {
        int firstResult = (pageId - 1) * MAX_RESULTS;
        String extendSQL = " WHERE t.inspector.id =" + userId + " AND extract(month from t.eventDate) = extract(month from CURRENT_DATE) ORDER BY t.eventDate ASC";
        return scheduleHistoryDAO.getObjects(firstResult, extendSQL);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItemHistory> getPastSHItemsByInspectorId(long userId, int pageId) {
        int firstResult = (pageId - 1) * MAX_RESULTS;
        LocalDate now = LocalDate.now();
        LocalDate earlier = now.minusMonths(1);
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("dd-MM-YYYY");
        String dateString = dateTimeFormatter.format(earlier);
        String extendSQL = " WHERE t.inspector.id =" + userId + " AND extract(month from t.eventDate) = extract(month from to_timestamp('" + dateString + "', 'dd-MM-YYYY')) ORDER BY t.eventDate ASC";
        return scheduleHistoryDAO.getObjects(firstResult, extendSQL);
    }

    @Override
    public Long getSHCurrentPages(long userId) {
        String extendSQL = "WHERE t.inspector.id=" + userId + " AND extract(month from t.eventDate) = extract(month from CURRENT_DATE) GROUP BY t.inspector.id";
        try {
            return scheduleHistoryDAO.getPages(extendSQL);
        } catch (NoResultException e) {
            return 1L;
        }

    }

    @Override
    public Long getSHPastPages(long userId) {
        LocalDate now = LocalDate.now();
        LocalDate earlier = now.minusMonths(1);
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("dd-MM-YYYY");
        String dateString = dateTimeFormatter.format(earlier.with(TemporalAdjusters.next(DayOfWeek.MONDAY)));
        String extendSQL = "WHERE t.inspector.id=" + userId + " AND extract(month from t.eventDate) = extract(month from to_timestamp('" + dateString + "', 'dd-MM-YYYY')) GROUP BY t.inspector.id";
        try {
            return scheduleHistoryDAO.getPages(extendSQL);
        } catch (NoResultException e) {
            return 1L;
        }

    }
}
