package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.ListAttribute;
import javax.persistence.metamodel.SetAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Utility.class)
public abstract class Utility_ {

	public static volatile SingularAttribute<Utility, String> webSite;
	public static volatile SingularAttribute<Utility, String> identificationCode;
	public static volatile SingularAttribute<Utility, Address> address;
	public static volatile SingularAttribute<Utility, String> phoneNumber;
	public static volatile SingularAttribute<Utility, User> manager;
	public static volatile SetAttribute<Utility, Counter> counters;
	public static volatile ListAttribute<Utility, User> inspectors;
	public static volatile SingularAttribute<Utility, String> name;
	public static volatile SingularAttribute<Utility, Boolean> active;
	public static volatile SingularAttribute<Utility, String> logo;
	public static volatile SingularAttribute<Utility, Long> id;

	public static final String WEB_SITE = "webSite";
	public static final String IDENTIFICATION_CODE = "identificationCode";
	public static final String ADDRESS = "address";
	public static final String PHONE_NUMBER = "phoneNumber";
	public static final String MANAGER = "manager";
	public static final String COUNTERS = "counters";
	public static final String INSPECTORS = "inspectors";
	public static final String NAME = "name";
	public static final String ACTIVE = "active";
	public static final String LOGO = "logo";
	public static final String ID = "id";

}

