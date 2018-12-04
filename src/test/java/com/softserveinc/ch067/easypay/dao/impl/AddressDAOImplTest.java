package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IAddressDAO;
import com.softserveinc.ch067.easypay.dao.impl.dataprovider.AddressTestDataProvider;
import com.softserveinc.ch067.easypay.model.*;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.hamcrest.Matchers;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.jdbc.SqlGroup;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;

@RunWith(JUnitParamsRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class, AddressDAOImpl.class})
@SqlGroup({
        @Sql(scripts = "classpath:db/AddressDAO.sql", executionPhase = BEFORE_TEST_METHOD),
        @Sql(scripts = "classpath:db/CleanTables.sql", executionPhase = AFTER_TEST_METHOD)
})
public class AddressDAOImplTest {

    private static final List<Boolean> EXPECTED_FROM_IS_UNIQUENESS = Arrays.asList(true, false);

    @Autowired
    private IAddressDAO addressDAO;

    @ClassRule
    public static final SpringClassRule SCR = new SpringClassRule();

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    @Test
    @Parameters(source = AddressTestDataProvider.class, method = "getAddressTestList")
    public void isUniqueness(Address[] testAddress) {
        List<Boolean> result = new ArrayList<>();
        Arrays.stream(testAddress).forEach(address -> result.add(addressDAO.isUniqueness(address)));
        assertThat(EXPECTED_FROM_IS_UNIQUENESS, Matchers.containsInAnyOrder(result.toArray()));
    }
}
