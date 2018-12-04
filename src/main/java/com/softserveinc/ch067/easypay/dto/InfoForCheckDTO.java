package com.softserveinc.ch067.easypay.dto;

import com.softserveinc.ch067.easypay.model.PaymentsHistory;
import com.softserveinc.ch067.easypay.util.PaymentsHistoryPDFDetails;

public class InfoForCheckDTO {

    private PaymentsHistoryPDFDetails details;
    private PaymentsHistory paymentsHistory;

    public InfoForCheckDTO() {
    }

    public InfoForCheckDTO(PaymentsHistoryPDFDetails details, PaymentsHistory paymentsHistory) {
        this.details = details;
        this.paymentsHistory = paymentsHistory;
    }

    public PaymentsHistoryPDFDetails getDetails() {
        return details;
    }

    public void setDetails(PaymentsHistoryPDFDetails details) {
        this.details = details;
    }

    public PaymentsHistory getPaymentsHistory() {
        return paymentsHistory;
    }

    public void setPaymentsHistory(PaymentsHistory paymentsHistory) {
        this.paymentsHistory = paymentsHistory;
    }
}
