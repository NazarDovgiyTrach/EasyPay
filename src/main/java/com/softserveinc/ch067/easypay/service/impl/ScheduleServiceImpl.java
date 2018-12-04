package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IScheduleItemDAO;
import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import com.softserveinc.ch067.easypay.util.GeoUtil;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

import static java.time.temporal.TemporalAdjusters.lastDayOfMonth;

@Service
public class ScheduleServiceImpl implements IScheduleService {
    private final IScheduleItemDAO scheduleItemDAO;

    @Autowired
    public ScheduleServiceImpl(IScheduleItemDAO scheduleItemDAO, ModelMapper modelMapper) {
        this.scheduleItemDAO = scheduleItemDAO;
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItem> getAll() {
        return scheduleItemDAO.getAll();
    }

    @Override
    @Transactional(readOnly = true)
    public ScheduleItem getById(Long id, boolean withAddress, boolean withInspector) {
        List<String> attributeGraph = new ArrayList<>();

        if (withAddress) {
            attributeGraph.add("address");
        }

        if (withInspector) {
            attributeGraph.add("inspector");
        }

        return scheduleItemDAO.getById(id, EntityGraphType.FETCH, attributeGraph.toArray(new String[0]));
    }

    @Override
    @Transactional
    public void create(ScheduleItem scheduleItem) {
        scheduleItemDAO.create(scheduleItem);
    }

    @Override
    @Transactional
    public void update(ScheduleItem scheduleItem) {
        scheduleItemDAO.update(scheduleItem);
    }

    @Override
    @Transactional
    public void delete(ScheduleItem scheduleItem) {
        scheduleItemDAO.delete(scheduleItem);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        scheduleItemDAO.delete(getById(id, false, false));
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItem> getListByUserId(Long id, boolean withAddress, boolean withInspector) {
        List<String> attributeGraph = new ArrayList<>();

        if (withAddress) {
            attributeGraph.add("address");
        }

        if (withInspector) {
            attributeGraph.add("inspector");
        }

        return scheduleItemDAO.getListByUserId(id, EntityGraphType.FETCH, attributeGraph.toArray(new String[0]));
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScheduleItem> getOverdueItems() {
        return scheduleItemDAO.getOverdueItems();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isExist(Address address, List<User> inspectors) {
        List<Long> inspectorsId = inspectors
                .stream()
                .map(User::getId)
                .collect(Collectors.toList());
        return !inspectorsId.isEmpty() && scheduleItemDAO.isExist(address.getId(), inspectorsId);
    }

    @Override
    @Transactional(readOnly = true)
    public LocalDate getLeastBusyDayOfInspector(User inspector) {
        Map<LocalDate, Integer> countInDays = new HashMap<>();
        LocalDate now = LocalDate.now();

        for (int i = now.getDayOfMonth(); i <= now.with(lastDayOfMonth()).getDayOfMonth(); i++) {
            LocalDate date = now.withDayOfMonth(i);
            int count = ((Number) scheduleItemDAO.getCountItemsByUserIdAndDate(inspector.getId(), date)).intValue();
            countInDays.put(date, count);
        }

        return Collections.min(countInDays.entrySet(), Comparator.comparing(Map.Entry::getValue)).getKey();
    }

    @Override
    @Transactional
    public void addScheduleItemForCall(Utility utility, Timestamp date, Address address) {
        List<User> inspectors = utility.getInspectors()
                .stream()
                .filter(i -> !i.getAddresses().isEmpty())
                .collect(Collectors.toList());
        if (!inspectors.isEmpty()) {
            User inspector = getInspectorForCall(inspectors, date, address);
            ScheduleItem scheduleItem = new ScheduleItem();
            scheduleItem.setAddress(address);
            scheduleItem.setEventDate(date.toLocalDateTime().toLocalDate());
            scheduleItem.setInspector(inspector);
            scheduleItem.setRepeat(false);
            scheduleItemDAO.create(scheduleItem);
        }
    }

    @Override
    @Transactional
    public User getInspectorForCall(List<User> inspectors, Timestamp date, Address address) {
        List<User> inspectorsInRange = new ArrayList<>();
        Map<User, Double> distance = new HashMap<>();
        inspectors.forEach(i -> distance.put(i, GeoUtil.getDistance(i.getAddresses().iterator().next(), address)));
        distance.forEach((i, d) -> {
            if (d <= 5000.0) {
                inspectorsInRange.add(i);
            }
        });
        if (!inspectorsInRange.isEmpty()) {
            return findLeastBusyInspector(inspectorsInRange, date.toLocalDateTime().toLocalDate());
        } else
            return findLeastBusyInspector(inspectors, date.toLocalDateTime().toLocalDate());
    }

    @Override
    @Transactional
    public void deleteAllItemsForInspector(Long idInspector) {
        getListByUserId(idInspector, false, false).forEach(this::delete);
    }

    private User findLeastBusyInspector(List<User> inspectors, LocalDate date) {
        User inspectorToCall = new User();
        int min = Integer.MAX_VALUE;
        for (User inspector : inspectors) {
            int inspectorScheduleCount = ((Number) scheduleItemDAO.getCountItemsByUserIdAndDate(inspector.getId(), date)).intValue();
            if (inspectorScheduleCount < min) {
                min = inspectorScheduleCount;
                inspectorToCall = inspector;
            }
        }
        return inspectorToCall;
    }

}
