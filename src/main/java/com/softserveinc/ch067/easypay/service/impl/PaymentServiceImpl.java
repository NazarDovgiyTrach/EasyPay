package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IPaymentService;
import java.util.HashMap;
import java.util.Map;

import com.stripe.exception.*;
import com.stripe.model.*;
import org.springframework.stereotype.Service;

import com.stripe.Stripe;

@Service("paymentService")
public class PaymentServiceImpl implements IPaymentService {

    private static final String TEST_STRIPE_SECRET_KEY = "sk_test_88lDGCHVJSFZIqm2dDu4IaFk";

    public PaymentServiceImpl() {
        Stripe.apiKey = TEST_STRIPE_SECRET_KEY;
    }
    @Override
    public String createCustomer(User user) {

        Map<String, Object> customerParams = new HashMap<>();
        customerParams.put("description",
                user.getName() + " " + user.getSurname());
        customerParams.put("email", user.getEmail());
        String id = null;

        try {
            // Create customer
            Customer stripeCustomer = Customer.create(customerParams);
            id = stripeCustomer.getId();
        } catch (CardException e) {
            // Transaction failure
        } catch (RateLimitException e) {
            // Too many requests made to the API too quickly
        } catch (InvalidRequestException e) {
            // Invalid parameters were supplied to Stripe's API
        } catch (AuthenticationException e) {
            // Authentication with Stripe's API failed (wrong API key?)
        } catch (APIConnectionException e) {
            // Network communication with Stripe failed
        } catch (StripeException e) {
            // Generic error
        } catch (Exception e) {
            // Something else happened unrelated to Stripe
        }

        return id;
    }
    @Override
    public void chargeCreditCard(String token, double totalSum) throws CardException, APIException, AuthenticationException, InvalidRequestException, APIConnectionException {

        // Stripe requires the charge amount to be in cents
        Long chargeAmountCents = (long) ((totalSum/27) * 100);

        Map<String, Object> chargeParams = new HashMap<>();
        chargeParams.put("amount", chargeAmountCents);
        chargeParams.put("currency", "usd");
        chargeParams.put("description", "Monthly Charges");
        chargeParams.put("source", token);

        try {
            Charge charge = Charge.create(chargeParams);
        } catch (CardException e) {
            // Transaction was declined
        } catch (RateLimitException e) {
            // Too many requests made to the API too quickly
        } catch (InvalidRequestException e) {
            // Invalid parameters were supplied to Stripe's API
        } catch (AuthenticationException e) {
            // Authentication with Stripe's API failed (wrong API key?)
        } catch (APIConnectionException e) {
            // Network communication with Stripe failed
        } catch (StripeException e) {
            // Generic error
        } catch (Exception e) {
            // Something else happened unrelated to Stripe
        }
    }
}
