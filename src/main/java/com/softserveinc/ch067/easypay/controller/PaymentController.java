package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.service.IPaymentService;
import com.stripe.exception.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class PaymentController {
    private final IPaymentService paymentService;

    @Autowired
    public PaymentController(IPaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @PostMapping(value = "/user/payWithCard")
    public void pay(@RequestParam(name = "sum") double sum,
                    @RequestBody String token){
        try {
            paymentService.chargeCreditCard(token, sum);
        } catch (CardException e) {
            e.printStackTrace();
        } catch (APIException e) {
            e.printStackTrace();
        } catch (AuthenticationException e) {
            e.printStackTrace();
        } catch (InvalidRequestException e) {
            e.printStackTrace();
        } catch (APIConnectionException e) {
            e.printStackTrace();
        }
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e){
        return new ResponseEntity<>("responseServerError",
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
