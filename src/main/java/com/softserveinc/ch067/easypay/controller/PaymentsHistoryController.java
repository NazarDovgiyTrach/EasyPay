package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.model.PaymentsHistory;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IGoogleDriveService;
import com.softserveinc.ch067.easypay.service.IPaymentsHistoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class PaymentsHistoryController {
    private final IPaymentsHistoryService paymentsHistoryService;
    private final IGoogleDriveService googleDriveService;

    @Autowired
    public PaymentsHistoryController(IPaymentsHistoryService paymentsHistoryService, IGoogleDriveService googleDriveService) {
        this.paymentsHistoryService = paymentsHistoryService;
        this.googleDriveService = googleDriveService;
    }

    @GetMapping("/paymentsHistories")
    List<PaymentsHistory> getAll(){
        return paymentsHistoryService.getAll();
    }

    @GetMapping("/user/payments/history/all")
    List<PaymentsHistory> getAllByUserId(@AuthenticationPrincipal User user){
        return paymentsHistoryService.getAllByUserId(user.getId());
    }

    @GetMapping("/user/address/{addressId}/utility/{utilityId}/payments/history")
    List<PaymentsHistory> getAllByAddressAndUtility(@PathVariable("utilityId") Long utilityId,
                                                    @PathVariable("addressId") Long addressId){
        return paymentsHistoryService.getAllByAddressAndUtility(addressId, utilityId);
    }

    @GetMapping("/user/address/{addressId}/utility/{utilityId}/payments/history/{pageId}")
    List<PaymentsHistory> getLimitedByAddressAndUtility(@PathVariable("utilityId") Long utilityId,
                                                        @PathVariable("addressId") Long addressId,
                                                        @PathVariable("pageId") int pageId){
        return paymentsHistoryService.getLimitedByAddressAndUtility(addressId, utilityId, pageId);
    }

    @GetMapping("/user/address/{addressId}/utility/{utilityId}/payments/history/pages")
    Long getPages(@PathVariable("addressId") Long addressId,
                     @PathVariable("utilityId") Long utilityId){
        return paymentsHistoryService.getPages(addressId, utilityId);
    }

    @GetMapping("/user/payments/history/{id}")
    PaymentsHistory getById(@PathVariable("id") Long id){
        return paymentsHistoryService.getById(id);
    }

    @GetMapping("/user/payments/history/check")
    ResponseEntity<String> getCheck(@RequestParam("fileId") String id) {
        return new ResponseEntity<>(googleDriveService.getFileUrlByFileId(id),
                                    HttpStatus.OK);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e){
        return new ResponseEntity<>("responseServerError",
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
