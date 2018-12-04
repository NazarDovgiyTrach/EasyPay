package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SetAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Street.class)
public abstract class Street_ {

	public static volatile SingularAttribute<Street, City> city;
	public static volatile SingularAttribute<Street, String> name;
	public static volatile SetAttribute<Street, House> houses;
	public static volatile SingularAttribute<Street, Long> id;

	public static final String CITY = "city";
	public static final String NAME = "name";
	public static final String HOUSES = "houses";
	public static final String ID = "id";

}

