package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.EmailToken;
import com.softserveinc.ch067.easypay.model.User;

public interface IEmailTokenService {
    EmailToken getByUserId(long userId);
    EmailToken getByToken(String token);
    void create(EmailToken emailToken);
    void delete(EmailToken emailToken);
    EmailToken buildToken(User user);
}
