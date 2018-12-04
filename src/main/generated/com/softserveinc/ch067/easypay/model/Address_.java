package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Address.class)
public abstract class Address_ {

	public static volatile SingularAttribute<Address, Double> lng;
	public static volatile SingularAttribute<Address, City> city;
	public static volatile SingularAttribute<Address, Street> street;
	public static volatile SingularAttribute<Address, Flat> flat;
	public static volatile SingularAttribute<Address, Long> id;
	public static volatile SingularAttribute<Address, Region> region;
	public static volatile SingularAttribute<Address, Boolean> isActive;
	public static volatile SingularAttribute<Address, House> house;
	public static volatile SingularAttribute<Address, Double> lat;

	public static final String LNG = "lng";
	public static final String CITY = "city";
	public static final String STREET = "street";
	public static final String FLAT = "flat";
	public static final String ID = "id";
	public static final String REGION = "region";
	public static final String IS_ACTIVE = "isActive";
	public static final String HOUSE = "house";
	public static final String LAT = "lat";

}

