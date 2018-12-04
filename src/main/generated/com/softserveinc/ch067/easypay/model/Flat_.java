package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Flat.class)
public abstract class Flat_ {

	public static volatile SingularAttribute<Flat, String> number;
	public static volatile SingularAttribute<Flat, Long> id;
	public static volatile SingularAttribute<Flat, House> house;

	public static final String NUMBER = "number";
	public static final String ID = "id";
	public static final String HOUSE = "house";

}

