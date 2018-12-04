package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(EmailToken.class)
public abstract class EmailToken_ {

	public static volatile SingularAttribute<EmailToken, Long> id;
	public static volatile SingularAttribute<EmailToken, User> user;
	public static volatile SingularAttribute<EmailToken, String> token;

	public static final String ID = "id";
	public static final String USER = "user";
	public static final String TOKEN = "token";

}

