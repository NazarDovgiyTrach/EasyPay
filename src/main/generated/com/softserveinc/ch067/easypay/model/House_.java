package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SetAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(House.class)
public abstract class House_ {

	public static volatile SingularAttribute<House, String> number;
	public static volatile SetAttribute<House, Flat> flats;
	public static volatile SingularAttribute<House, Street> street;
	public static volatile SingularAttribute<House, Long> id;

	public static final String NUMBER = "number";
	public static final String FLATS = "flats";
	public static final String STREET = "street";
	public static final String ID = "id";

}

