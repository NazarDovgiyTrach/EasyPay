package com.softserveinc.ch067.easypay.util;

import com.softserveinc.ch067.easypay.dto.CounterDTO;

import java.sql.Timestamp;
import java.util.Set;

public class PaymentsHistoryPDFDetails {
    private Double rate;
    private Double oldDebt;
    private Double newDebt;
    private Set<CounterDTO> counters;
    private String address;
    private String serviceName;
    private String userName;
    private String userEmail;
    private Timestamp paymentTime;
    private String fileName;

    public PaymentsHistoryPDFDetails() {
    }

    public PaymentsHistoryPDFDetails(Double rate, Double oldDebt, Double newDebt, Set<CounterDTO> counters, String address, String serviceName) {
        this.rate = rate;
        this.oldDebt = oldDebt;
        this.newDebt = newDebt;
        this.counters = counters;
        this.address = address;
        this.serviceName = serviceName;
    }

    public void setRate(Double rate) {
        this.rate = rate;
    }

    public void setOldDebt(Double oldDebt) {
        this.oldDebt = oldDebt;
    }

    public void setNewDebt(Double newDebt) {
        this.newDebt = newDebt;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public void setUserEmail(String userEmail) {
        this.userEmail = userEmail;
    }

    public Double getRate() {
        return rate;
    }

    public void setRate(double rate) {
        this.rate = rate;
    }

    public Double getOldDebt() {
        return oldDebt;
    }

    public void setOldDebt(double oldDebt) {
        this.oldDebt = oldDebt;
    }

    public Double getNewDebt() {
        return newDebt;
    }

    public void setNewDebt(double newDebt) {
        this.newDebt = newDebt;
    }

    public Set<CounterDTO> getCounters() {
        return counters;
    }

    public void setCounters(Set<CounterDTO> counters) {
        this.counters = counters;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public Timestamp getPaymentTime() {
        return paymentTime;
    }

    public void setPaymentTime(Timestamp paymentTime) {
        this.paymentTime = paymentTime;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    @Override
    public String toString() {
        return "PaymentsHistoryPDFDetails{" +
                "rate=" + rate +
                ", oldDebt=" + oldDebt +
                ", newDebt=" + newDebt +
                ", counters=" + counters +
                ", address='" + address + '\'' +
                ", serviceName='" + serviceName + '\'' +
                ", userName='" + userName + '\'' +
                ", userEmail='" + userEmail + '\'' +
                ", paymentTime=" + paymentTime +
                ", fileName='" + fileName + '\'' +
                '}';
    }
}
