package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Debt.class)
public abstract class Debt_ {

	public static volatile SingularAttribute<Debt, LocalDate> lastCounterReminderSend;
	public static volatile SingularAttribute<Debt, LocalDate> lastPaid;
	public static volatile SingularAttribute<Debt, Utility> utility;
	public static volatile SingularAttribute<Debt, Long> id;
	public static volatile SingularAttribute<Debt, Double> value;
	public static volatile SingularAttribute<Debt, LocalDate> lastDebtReminderSend;

	public static final String LAST_COUNTER_REMINDER_SEND = "lastCounterReminderSend";
	public static final String LAST_PAID = "lastPaid";
	public static final String UTILITY = "utility";
	public static final String ID = "id";
	public static final String VALUE = "value";
	public static final String LAST_DEBT_REMINDER_SEND = "lastDebtReminderSend";

}

