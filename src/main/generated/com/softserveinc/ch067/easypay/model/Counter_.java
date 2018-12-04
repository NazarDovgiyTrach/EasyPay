package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Counter.class)
public abstract class Counter_ {

	public static volatile SingularAttribute<Counter, LocalDate> lastUpdated;
	public static volatile SingularAttribute<Counter, Address> address;
	public static volatile SingularAttribute<Counter, Boolean> active;
	public static volatile SingularAttribute<Counter, Boolean> fixed;
	public static volatile SingularAttribute<Counter, Long> id;
	public static volatile SingularAttribute<Counter, Long> oldValue;
	public static volatile SingularAttribute<Counter, User> user;
	public static volatile SingularAttribute<Counter, Debt> debt;
	public static volatile SingularAttribute<Counter, Long> currentValue;

	public static final String LAST_UPDATED = "lastUpdated";
	public static final String ADDRESS = "address";
	public static final String ACTIVE = "active";
	public static final String FIXED = "fixed";
	public static final String ID = "id";
	public static final String OLD_VALUE = "oldValue";
	public static final String USER = "user";
	public static final String DEBT = "debt";
	public static final String CURRENT_VALUE = "currentValue";

}

