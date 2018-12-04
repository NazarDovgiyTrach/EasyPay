package com.softserveinc.ch067.easypay.model;

import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(RatingListItem.class)
public abstract class RatingListItem_ {

	public static volatile SingularAttribute<RatingListItem, User> rater;
	public static volatile SingularAttribute<RatingListItem, Double> ratingValue;
	public static volatile SingularAttribute<RatingListItem, Long> id;
	public static volatile SingularAttribute<RatingListItem, User> ratedUser;

	public static final String RATER = "rater";
	public static final String RATING_VALUE = "ratingValue";
	public static final String ID = "id";
	public static final String RATED_USER = "ratedUser";

}

