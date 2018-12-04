package com.softserveinc.ch067.easypay.cron;

import com.softserveinc.ch067.easypay.service.IPlanningPriceUpdateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
public class PlanningPriceUpdateCron {

    private final IPlanningPriceUpdateService planningPriceUpdateService;

    @Autowired
    public PlanningPriceUpdateCron(IPlanningPriceUpdateService planningPriceUpdateService) {
        this.planningPriceUpdateService = planningPriceUpdateService;
    }

    /**
     * Method executing every 1st day of month at 12:00 AM. Executes service method which set new price to utility
     */
    @Scheduled(cron = "0 0 0 1 1/1 ?")
    public void planningPriceUpdate() { planningPriceUpdateService.updatePrice(); }
}
