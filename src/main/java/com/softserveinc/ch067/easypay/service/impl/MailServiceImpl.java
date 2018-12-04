package com.softserveinc.ch067.easypay.service.impl;


import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.Debt;
import com.softserveinc.ch067.easypay.model.EmailToken;
import com.softserveinc.ch067.easypay.service.IMailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.io.File;
import java.util.Locale;


@Service
public class MailServiceImpl implements IMailService {

    private static final String PAYMENT_CHECK_TITLE = "paymentCheckTitle";
    private static final String PAYMENT_CHECK_MESSAGE = "paymentCheckMessage";

    private final String checksDir;

    private final TemplateEngine templateEngine;

    private final MessageSource messageSource;

    private final JavaMailSender javaMailSender;

    @Autowired
    public MailServiceImpl(@Qualifier(value = "checksDir") String checksDir,
                           TemplateEngine templateEngine,
                           @Qualifier("localeMessageSource") MessageSource messageSource,
                           JavaMailSender javaMailSender) {
        this.checksDir = checksDir;
        this.templateEngine = templateEngine;
        this.messageSource = messageSource;
        this.javaMailSender = javaMailSender;
    }

    @Override
    public void sendPasswordResetTokenMessageToEmail(EmailToken emailToken, String email, String appBaseUrl,
                                                     Locale locale) {
        String textTemplate = messageSource.getMessage("passwordResetMessage", null, locale) + " " + appBaseUrl +
                "/resetPassword?token=" + emailToken.getToken();
        setEmailTokenMessage(email, messageSource.getMessage("resetPasswordMailSubject", null, locale),
                textTemplate);
    }

    @Override
    public void sendRegistrationConfirmationToken(EmailToken emailToken, String email, String appBaseUrl, Locale locale) {
        String textTemplate = messageSource.getMessage("ConfirmRegistrationMessage", null, locale) + " " + appBaseUrl +
                "/confirmRegistration?token=" + emailToken.getToken();
        setEmailTokenMessage(email, messageSource.getMessage("confirmRegistration", null, locale), textTemplate);
    }

    private void setEmailTokenMessage(String toEmail, String subject, String text) {
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setTo(toEmail);
        simpleMailMessage.setText(text);
        simpleMailMessage.setSubject(subject);
        javaMailSender.send(simpleMailMessage);
    }

    @Override
    public void sendPasswordAndLogin(EmailToken emailToken, String email, String password, String appBaseUrl, Locale locale) {
        String textTemplate = messageSource.getMessage("sendPasswordAndLoginFirstPart", null, locale) + " " + email +
                " " + messageSource.getMessage("sendPasswordAndLoginFirstPart", null, locale) + " " + password
                + " " + messageSource.getMessage("ConfirmRegistrationMessage", null, locale)
                + " " + appBaseUrl + "/continue?token="
                + emailToken.getToken();
        setEmailTokenMessage(email, messageSource.getMessage("adminRegisterTitle", null, locale), textTemplate);
    }

    @Override
    public void sendCheckFile(String email, String fileName, Locale locale) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);

        File file = new File(checksDir + "/" + email + "/" + fileName);

        helper.setTo(email);
        helper.setText(messageSource.getMessage(PAYMENT_CHECK_MESSAGE, null, locale));
        helper.setSubject(messageSource.getMessage(PAYMENT_CHECK_TITLE, null, locale));
        helper.addAttachment(fileName, file);

        javaMailSender.send(message);
    }

    @Override
    public void sendCheckFile(String email, GeneratedFileDTO fileInfo, Locale locale) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);

        helper.setTo(email);
        helper.setText(messageSource.getMessage(PAYMENT_CHECK_MESSAGE, null, locale));
        helper.setSubject(messageSource.getMessage(PAYMENT_CHECK_TITLE, null, locale));
        helper.addAttachment(fileInfo.getFileName(), new ByteArrayResource(fileInfo.getFileContent()));

        javaMailSender.send(message);
    }

    @Override
    public void sendDebtReminder(DebtInfoForMailingDTO debtInfoForMailingDTO) throws MessagingException {
        String subject = String.format("EASY PAY - %s unpaid", debtInfoForMailingDTO.getUtilityName());
        Context context = getContextFromDebtInfoForMailingDTO(debtInfoForMailingDTO);
        sendMessageHTML(debtInfoForMailingDTO.getUserEmail(),subject,"debt-reminder.html",context);
    }

    @Override
    public void sendCounterReminder(DebtInfoForMailingDTO debtInfoForMailingDTO) throws MessagingException {
        String subject = String.format("EASY PAY - %s counter unreported", debtInfoForMailingDTO.getUtilityName());
        Context context = getContextFromDebtInfoForMailingDTO(debtInfoForMailingDTO);
        sendMessageHTML(debtInfoForMailingDTO.getUserEmail(),subject,"counter-reminder.html",context);
    }

    private void sendMessageHTML(String receiverEmail,String messageSubject,String thymeleafTemplateFile,
                                 Context context)
            throws MessagingException{
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        mimeMessage.setSubject(messageSubject);
        String htmlContent = templateEngine.process(thymeleafTemplateFile, context);
        mimeMessage.setText(htmlContent, "UTF-8", "html");
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, false, "UTF-8");
//        mimeMessageHelper.setTo(receiverEmail);
        mimeMessageHelper.setTo("plaer12345@gmail.com");
        javaMailSender.send(mimeMessage);
    }

    private Context getContextFromDebtInfoForMailingDTO(DebtInfoForMailingDTO debtInfoForMailingDTO){
        Context context = new Context();
        context.setVariable("serviceName", debtInfoForMailingDTO.getUtilityName());
        context.setVariable("dept", debtInfoForMailingDTO.getDebt());
        context.setVariable("userFullName", String.format("%s %s", debtInfoForMailingDTO.getUserName(),
                debtInfoForMailingDTO.getUserSurname()));
        context.setVariable("address", debtInfoForMailingDTO.getAddress().getFullAddressString());
        return context;
    }


}