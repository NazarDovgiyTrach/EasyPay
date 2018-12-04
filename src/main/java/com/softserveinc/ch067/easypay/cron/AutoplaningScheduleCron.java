package com.softserveinc.ch067.easypay.cron;

import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.IAddressService;
import com.softserveinc.ch067.easypay.service.IScheduleService;
import com.softserveinc.ch067.easypay.service.IUnscheduledAddressesService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import com.softserveinc.ch067.easypay.util.GeoUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
@EnableScheduling
@SuppressWarnings("unchecked")
public class AutoplaningScheduleCron {

    private final IUtilityService utilityService;
    private final IScheduleService scheduleService;
    private final IUnscheduledAddressesService unscheduledAddressesService;

    @Autowired
    public AutoplaningScheduleCron(IUtilityService utilityService,
                                   IScheduleService scheduleService,
                                   IUnscheduledAddressesService unscheduledAddressesService) {
        this.utilityService = utilityService;
        this.scheduleService = scheduleService;
        this.unscheduledAddressesService = unscheduledAddressesService;
    }

    @Scheduled(fixedRate = 36000000)
    public void autoplaningScheduleCron() {
        List<Utility> utilities = utilityService.getAll(false, false, true, true);

        for (Utility utility : utilities) {
            List<User> inspectors = utility
                    .getInspectors()
                    .stream()
                    .filter(i -> !i.getAddresses().isEmpty())
                    .collect(Collectors.toList());

            List<Address> addresses = utility
                    .getCounters()
                    .stream()
                    .map(Counter::getAddress)
                    .filter(a -> !scheduleService.isExist(a, inspectors))
                    .collect(Collectors.toList());

            Map<Address, User> listForPlanning = new HashMap<>();
            List<Address> listForNonPlannedAddress = new ArrayList<>();

            addresses.forEach(a -> {
                Map<User, Double> distance = new HashMap<>();

                inspectors.forEach(i -> distance.put(i, GeoUtil.getDistance(i.getAddresses().iterator().next(), a)));

                if (!distance.isEmpty() && Collections.min(distance.values()) <= 1000.0) {
                    listForPlanning.put(a, Collections.min(distance.entrySet(), Comparator.comparing(Map.Entry::getValue)).getKey());
                } else {
                    listForNonPlannedAddress.add(a);
                }
            });

            listForPlanning.forEach((address, inspector) -> {
                ScheduleItem scheduleItem = new ScheduleItem(inspector, address, scheduleService.getLeastBusyDayOfInspector(inspector), true);
                scheduleService.create(scheduleItem);
            });

            List<UnscheduledAddresses> unscheduledAddresses = unscheduledAddressesService.getByUtility(utility, true, false);

            listForNonPlannedAddress.forEach(address -> {
                List<UnscheduledAddresses> ua = unscheduledAddresses
                        .stream()
                        .filter(u -> u.getAddress().equals(address))
                        .collect(Collectors.toList());

                if (ua.isEmpty()) {
                    unscheduledAddressesService.create(new UnscheduledAddresses(address, utility));
                } else {
                    unscheduledAddresses.remove(ua.get(0));
                }
            });

            unscheduledAddresses.forEach(unscheduledAddressesService::delete);
        }

    }
}
