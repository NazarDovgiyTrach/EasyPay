package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SetAttribute;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(User.class)
public abstract class User_ {

	public static volatile SingularAttribute<User, LocalDate> lastLogin;
	public static volatile SingularAttribute<User, String> password;
	public static volatile SetAttribute<User, Address> addresses;
	public static volatile SingularAttribute<User, Role> role;
	public static volatile SingularAttribute<User, String> phoneNumber;
	public static volatile SingularAttribute<User, UserStatus> userStatus;
	public static volatile SingularAttribute<User, String> surname;
	public static volatile SingularAttribute<User, String> name;
	public static volatile SingularAttribute<User, String> StripeCustomerId;
	public static volatile SingularAttribute<User, Long> id;
	public static volatile SingularAttribute<User, String> avatar;
	public static volatile SingularAttribute<User, String> email;

	public static final String LAST_LOGIN = "lastLogin";
	public static final String PASSWORD = "password";
	public static final String ADDRESSES = "addresses";
	public static final String ROLE = "role";
	public static final String PHONE_NUMBER = "phoneNumber";
	public static final String USER_STATUS = "userStatus";
	public static final String SURNAME = "surname";
	public static final String NAME = "name";
	public static final String STRIPE_CUSTOMER_ID = "StripeCustomerId";
	public static final String ID = "id";
	public static final String AVATAR = "avatar";
	public static final String EMAIL = "email";

}

