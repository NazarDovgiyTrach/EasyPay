package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.User;
import com.stripe.exception.*;
import com.stripe.model.Order;

public interface IPaymentService {
    String createCustomer(User user);
    void chargeCreditCard(String token, double totalSum) throws CardException, APIException, AuthenticationException, InvalidRequestException, APIConnectionException;
}
