package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(CurrentPrice.class)
public abstract class CurrentPrice_ {

	public static volatile SingularAttribute<CurrentPrice, LocalDate> date;
	public static volatile SingularAttribute<CurrentPrice, Double> price;
	public static volatile SingularAttribute<CurrentPrice, Utility> utility;
	public static volatile SingularAttribute<CurrentPrice, Boolean> active;
	public static volatile SingularAttribute<CurrentPrice, Long> currentPriceId;

	public static final String DATE = "date";
	public static final String PRICE = "price";
	public static final String UTILITY = "utility";
	public static final String ACTIVE = "active";
	public static final String CURRENT_PRICE_ID = "currentPriceId";

}

