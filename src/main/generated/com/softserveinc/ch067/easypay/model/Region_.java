package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SetAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Region.class)
public abstract class Region_ {

	public static volatile SetAttribute<Region, City> cities;
	public static volatile SingularAttribute<Region, String> name;
	public static volatile SingularAttribute<Region, Long> id;

	public static final String CITIES = "cities";
	public static final String NAME = "name";
	public static final String ID = "id";

}

