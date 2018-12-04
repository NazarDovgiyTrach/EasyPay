package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(ScheduleItemHistory.class)
public abstract class ScheduleItemHistory_ {

	public static volatile SingularAttribute<ScheduleItemHistory, Address> address;
	public static volatile SingularAttribute<ScheduleItemHistory, LocalDate> submitDate;
	public static volatile SingularAttribute<ScheduleItemHistory, String> comment;
	public static volatile SingularAttribute<ScheduleItemHistory, Long> id;
	public static volatile SingularAttribute<ScheduleItemHistory, User> inspector;
	public static volatile SingularAttribute<ScheduleItemHistory, LocalDate> eventDate;
	public static volatile SingularAttribute<ScheduleItemHistory, Status> status;

	public static final String ADDRESS = "address";
	public static final String SUBMIT_DATE = "submitDate";
	public static final String COMMENT = "comment";
	public static final String ID = "id";
	public static final String INSPECTOR = "inspector";
	public static final String EVENT_DATE = "eventDate";
	public static final String STATUS = "status";

}

