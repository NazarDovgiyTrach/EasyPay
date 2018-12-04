package com.softserveinc.ch067.easypay.model;

import java.time.LocalDate;
import javax.annotation.Generated;
import javax.persistence.metamodel.SingularAttribute;
import javax.persistence.metamodel.StaticMetamodel;

@Generated(value = "org.hibernate.jpamodelgen.JPAMetaModelEntityProcessor")
@StaticMetamodel(PaymentsHistory.class)
public abstract class PaymentsHistory_ {

	public static volatile SingularAttribute<PaymentsHistory, String> checkPath;
	public static volatile SingularAttribute<PaymentsHistory, Address> address;
	public static volatile SingularAttribute<PaymentsHistory, Double> paymentSum;
	public static volatile SingularAttribute<PaymentsHistory, Utility> utility;
	public static volatile SingularAttribute<PaymentsHistory, Long> id;
	public static volatile SingularAttribute<PaymentsHistory, String> googleDriveFileId;
	public static volatile SingularAttribute<PaymentsHistory, LocalDate> payDate;

	public static final String CHECK_PATH = "checkPath";
	public static final String ADDRESS = "address";
	public static final String PAYMENT_SUM = "paymentSum";
	public static final String UTILITY = "utility";
	public static final String ID = "id";
	public static final String GOOGLE_DRIVE_FILE_ID = "googleDriveFileId";
	public static final String PAY_DATE = "payDate";

}

