package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.EmailToken;

public interface IEmailTokenDAO {
    EmailToken getByUserId(long userId);
    EmailToken getByToken(String token);
    void create(EmailToken emailToken);
    void delete(EmailToken emailToken);
    EmailToken createWithEntityReturn(EmailToken emailToken);
}
