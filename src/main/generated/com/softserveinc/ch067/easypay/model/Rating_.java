package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(Rating.class)
public abstract class Rating_ {

	public static volatile SingularAttribute<Rating, Double> rating;
	public static volatile SingularAttribute<Rating, Long> id;
	public static volatile SingularAttribute<Rating, User> user;

	public static final String RATING = "rating";
	public static final String ID = "id";
	public static final String USER = "user";

}

