package com.softserveinc.ch067.easypay.cron;

import com.softserveinc.ch067.easypay.service.IDebtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
public class DebtCron {


    private final IDebtService debtService;


    @Qualifier("maxDeptPerQuery")
    private final Integer maxDeptPerQuery;

    @Autowired
    public DebtCron(IDebtService debtService,
                    @Qualifier("maxDeptPerQuery") Integer maxDeptPerQuery) {
        this.debtService = debtService;
        this.maxDeptPerQuery = maxDeptPerQuery;
    }

//    @Scheduled(fixedRate = 86400000)
    public void takeMoneyForFixedUtilities() {
        debtService.checkFixedCounters(maxDeptPerQuery);

    }
}
