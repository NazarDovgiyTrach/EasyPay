package com.softserveinc.ch067.easypay.cron;


import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.Debt;
import com.softserveinc.ch067.easypay.service.*;
import com.softserveinc.ch067.easypay.util.SMSSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Component
@EnableScheduling
public class SendReminderCron {

    private final IDebtService debtService;

    private final IMailService mailService;

    private final Integer maxMessagePerDay;

    private final SMSSender smsSender;

    @Autowired
    public SendReminderCron(IDebtService debtService,
                            IMailService mailService,
                            @Qualifier("maxMessagePerDay") Integer maxMessagePerDay,
                            SMSSender smsSender) {
        this.debtService = debtService;
        this.mailService = mailService;
        this.maxMessagePerDay = maxMessagePerDay;
        this.smsSender = smsSender;
    }

    private static final String SMS_DEBT_REMINDER = "EasyPay\n" + "Hello, %s :)\n" + "You must pay for utility %s.\n" + "Address: %s\n" + "Sum: %s";
    private static final String SMS_COUNTERS_REMINDER = "EasyPay\n" + "Hello, %s :)\n" + "You must enter your counters values.\n" + "Utility: %s\n" + "Address: %s";

//    @Scheduled(initialDelay = 60000000, fixedRate = 36000000)
    public void sendDebtReminder() {
        LocalDate firstDayOfMonth = LocalDate.now().withDayOfMonth(1);
        List<DebtInfoForMailingDTO> dtos = debtService.getUnpaid(firstDayOfMonth,firstDayOfMonth,maxMessagePerDay);
        List<Long> debtIds = new ArrayList<>();
        for (DebtInfoForMailingDTO dto : dtos) {
            try {

                mailService.sendDebtReminder(dto);
//                String userFullName = dto.getUserName() + " " + dto.getUserSurname();
//                smsSender.send_sms(dto.getPhoneNumber(), String.format(SMS_DEBT_REMINDER, userFullName, dto.getUtilityName(),
//                                                                    dto.getAddress().getFullAddressString(),
//                                    String.valueOf(dto.getDebt())), 0, "", "", 0, "EasyPay", "");
                debtIds.add(dto.getDebtId());
            } catch (MessagingException messageException) {
                //LoggerAspect will catch the exception
            }
            debtService.updateLastDebtReminderSend(debtIds);
        }
    }

//    @Scheduled(initialDelay = 60000000, fixedRate = 36000000)
    public void sendCounterReminder(){
        LocalDate fortyDaysAgo = LocalDate.now().minusDays(40);
        LocalDate thirtyDaysAgo = LocalDate.now().minusDays(30);
        List<DebtInfoForMailingDTO> dtos = debtService.getDebtWithUnreportedCounters(fortyDaysAgo,thirtyDaysAgo,maxMessagePerDay);
        List<Long> debtIds = new ArrayList<>();
        for (DebtInfoForMailingDTO dto : dtos) {
            try {
                mailService.sendCounterReminder(dto);
//                String userFullName = dto.getUserName() + " " + dto.getUserSurname();
//                smsSender.send_sms(dto.getPhoneNumber(), String.format(SMS_COUNTERS_REMINDER, userFullName, dto.getUtilityName(),
//                        dto.getAddress().getFullAddressString()), 0, "", "", 0, "EasyPay", "");
//                debtIds.add(dto.getDebtId());
            } catch (MessagingException messageException) {
                //LoggerAspect will catch the exception
            }
            debtService.updateLastCounterReminderSend(debtIds);
        }
    }
}
