package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(UnscheduledAddresses.class)
public abstract class UnscheduledAddresses_ {

	public static volatile SingularAttribute<UnscheduledAddresses, Address> address;
	public static volatile SingularAttribute<UnscheduledAddresses, Utility> utility;
	public static volatile SingularAttribute<UnscheduledAddresses, Long> id;

	public static final String ADDRESS = "address";
	public static final String UTILITY = "utility";
	public static final String ID = "id";

}

