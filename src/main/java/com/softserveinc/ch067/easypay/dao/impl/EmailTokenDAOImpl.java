package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IEmailTokenDAO;
import com.softserveinc.ch067.easypay.model.EmailToken;
import org.springframework.stereotype.Repository;

import javax.persistence.Query;

@Repository
public class EmailTokenDAOImpl extends CrudDAO<EmailToken> implements IEmailTokenDAO {

    @Override
    public EmailToken getByUserId(long userId) {
        Query query = entityManager.createQuery("select emailToken from EmailToken emailToken where emailToken.user.id = :userId", EmailToken.class);
        query.setParameter("userId", userId);
        return (EmailToken) query.getResultList().stream().findFirst().orElse(null);
    }

    @Override
    public EmailToken getByToken(String token) {
        Query query = entityManager.createQuery("select emailToken from EmailToken emailToken where emailToken.token = :token", EmailToken.class);
        query.setParameter("token", token);
        return (EmailToken) query.getResultList().stream().findFirst().orElse(null);
    }
}
