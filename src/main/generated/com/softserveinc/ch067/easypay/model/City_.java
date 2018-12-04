package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SetAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(City.class)
public abstract class City_ {

	public static volatile SetAttribute<City, Street> streets;
	public static volatile SingularAttribute<City, String> name;
	public static volatile SingularAttribute<City, Long> id;
	public static volatile SingularAttribute<City, Region> region;

	public static final String STREETS = "streets";
	public static final String NAME = "name";
	public static final String ID = "id";
	public static final String REGION = "region";

}

