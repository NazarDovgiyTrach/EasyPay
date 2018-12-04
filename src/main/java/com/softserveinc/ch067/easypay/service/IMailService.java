package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import com.softserveinc.ch067.easypay.model.Debt;
import com.softserveinc.ch067.easypay.model.EmailToken;

import javax.mail.MessagingException;
import java.util.Locale;

public interface IMailService {
    void sendPasswordResetTokenMessageToEmail(EmailToken emailToken, String email, String appBaseUrl, Locale locale);

    void sendRegistrationConfirmationToken(EmailToken emailToken, String email, String appBaseUrl, Locale locale);

    void sendPasswordAndLogin(EmailToken emailToken, String email, String password, String appBaseUrl, Locale locale);

    void sendCounterReminder(DebtInfoForMailingDTO debtInfoForMailingDTO) throws MessagingException;

    void sendDebtReminder(DebtInfoForMailingDTO debtInfoForMailingDTO) throws MessagingException;

    void sendCheckFile(String email, String fileName, Locale locale) throws MessagingException;

    void sendCheckFile(String email, GeneratedFileDTO fileInfo, Locale locale) throws MessagingException;
}
