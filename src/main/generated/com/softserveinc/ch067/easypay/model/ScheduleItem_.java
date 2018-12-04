package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(ScheduleItem.class)
public abstract class ScheduleItem_ {

	public static volatile SingularAttribute<ScheduleItem, Address> address;
	public static volatile SingularAttribute<ScheduleItem, Long> id;
	public static volatile SingularAttribute<ScheduleItem, User> inspector;
	public static volatile SingularAttribute<ScheduleItem, Boolean> isRepeat;
	public static volatile SingularAttribute<ScheduleItem, LocalDate> eventDate;

	public static final String ADDRESS = "address";
	public static final String ID = "id";
	public static final String INSPECTOR = "inspector";
	public static final String IS_REPEAT = "isRepeat";
	public static final String EVENT_DATE = "eventDate";

}

