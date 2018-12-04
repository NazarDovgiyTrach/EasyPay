package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(NewPrice.class)
public abstract class NewPrice_ {

	public static volatile SingularAttribute<NewPrice, CurrentPrice> currentPrice;
	public static volatile SingularAttribute<NewPrice, LocalDate> activationDate;
	public static volatile SingularAttribute<NewPrice, Double> newPrice;
	public static volatile SingularAttribute<NewPrice, Long> newPriceId;

	public static final String CURRENT_PRICE = "currentPrice";
	public static final String ACTIVATION_DATE = "activationDate";
	public static final String NEW_PRICE = "newPrice";
	public static final String NEW_PRICE_ID = "newPriceId";

}

