package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IEmailTokenDAO;
import com.softserveinc.ch067.easypay.model.EmailToken;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IEmailTokenService;
import com.softserveinc.ch067.easypay.service.IJwtTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Objects;

@Service
public class EmailTokenServiceImpl implements IEmailTokenService {

    private IEmailTokenDAO emailTokenDAO;
    private IJwtTokenService jwtTokenService;
    @Autowired
    public EmailTokenServiceImpl(IEmailTokenDAO emailTokenDAO, IJwtTokenService jwtTokenService) {
        this.emailTokenDAO = emailTokenDAO;
        this.jwtTokenService = jwtTokenService;
    }

    @Transactional(readOnly = true)
    @Override
    public EmailToken getByUserId(long userId) {
        return emailTokenDAO.getByUserId(userId);
    }

    @Transactional(readOnly = true)
    @Override
    public EmailToken getByToken(String token) {
        return emailTokenDAO.getByToken(token);
    }

    @Transactional
    @Override
    public void create(EmailToken emailToken) {
        emailTokenDAO.create(emailToken);
    }

    @Transactional
    @Override
    public void delete(EmailToken emailToken) {
        emailTokenDAO.delete(emailToken);
    }

    @Override
    @Transactional
    public EmailToken buildToken(User user){
        EmailToken newEmailToken = new EmailToken();
        newEmailToken.setUser(user);
        newEmailToken.setToken(jwtTokenService.generateAndGetEmailToken(user.getEmail()));
        return emailTokenDAO.createWithEntityReturn(newEmailToken);
    }
}
