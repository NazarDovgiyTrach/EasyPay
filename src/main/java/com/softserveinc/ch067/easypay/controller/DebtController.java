package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.dto.InfoForCheckDTO;
import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import com.softserveinc.ch067.easypay.exception.InvalidPaymentSumException;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IDebtService;
import com.softserveinc.ch067.easypay.service.IMailService;
import com.softserveinc.ch067.easypay.service.IPaymentsHistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.persistence.PersistenceException;
import java.util.Locale;

@RestController
public class DebtController {

    private final IDebtService debtService;
    private final IMailService mailService;
    private final IPaymentsHistoryService paymentsHistoryService;

    @Autowired
    public DebtController(IDebtService debtService,
                          IMailService mailService,
                          IPaymentsHistoryService paymentsHistoryService) {
        this.debtService = debtService;
        this.mailService = mailService;
        this.paymentsHistoryService = paymentsHistoryService;
    }

    private static final String WRONG_PAYMENT_SUM = "You have specified wrong payment sum!";

    private static final String RESPONSE_WRONG_PAYMENT_SUM = "responseWrongPaymentSum";
    private static final String RESPONSE_FILE_NOT_GENERATED = "responseFileNotGenerated";
    private static final String RESPONSE_ERROR_SENDING_EMAIL = "responseErrorSendingEmail";
    private static final String RESPONSE_SERVER_ERROR = "responseServerError";
    private static final String RESPONSE_CHECK_SENT = "responseCheckSent";

    @PostMapping("/user/debt/change")
    public ResponseEntity<String> payForUtilityAndSendCheck(@RequestParam("sum") double paymentSum,
                                                        @RequestParam("addressId") Long addressId,
                                                        @RequestParam("utilityId") Long utilityId,
                                                        @AuthenticationPrincipal User user,
                                                        Locale locale) throws Exception {
        if (paymentSum < 1) throw new InvalidPaymentSumException(WRONG_PAYMENT_SUM);

        InfoForCheckDTO checkInfo = debtService.payForUtility(paymentSum, addressId, utilityId, user);
        GeneratedFileDTO generatedFileInfo = paymentsHistoryService.generateCheck(checkInfo.getDetails(), checkInfo.getPaymentsHistory());

        mailService.sendCheckFile(user.getEmail(), generatedFileInfo, locale);

        return ResponseEntity.ok().body(RESPONSE_CHECK_SENT);
    }

    @PostMapping("/user/debt/change/check")
    public ResponseEntity<String> payForUtilityAndDownloadCheck(@RequestParam("sum") double paymentSum,
                                                                             @RequestParam("addressId") Long addressId,
                                                                             @RequestParam("utilityId") Long utilityId,
                                                                             @AuthenticationPrincipal User user) throws Exception{
        if (paymentSum < 1) throw new InvalidPaymentSumException(WRONG_PAYMENT_SUM);

        InfoForCheckDTO checkInfo = debtService.payForUtility(paymentSum, addressId, utilityId, user);
        GeneratedFileDTO generatedFileInfo = paymentsHistoryService.generateCheck(checkInfo.getDetails(), checkInfo.getPaymentsHistory());

        return new ResponseEntity<>(generatedFileInfo.getFileId(), HttpStatus.CREATED);

    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e){
        if (e instanceof InvalidPaymentSumException){
            return new ResponseEntity<>(RESPONSE_WRONG_PAYMENT_SUM,
                                                HttpStatus.BAD_REQUEST);
        } else if (e instanceof MessagingException){
            return new ResponseEntity<>(RESPONSE_ERROR_SENDING_EMAIL,
                                        HttpStatus.INTERNAL_SERVER_ERROR);
        } else if (e instanceof PersistenceException){
            return new ResponseEntity<>(RESPONSE_SERVER_ERROR,
                                        HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(RESPONSE_FILE_NOT_GENERATED,
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
