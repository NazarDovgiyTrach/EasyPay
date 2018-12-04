package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IUnscheduledAddressesDAO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.UnscheduledAddresses;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.hibernate.Hibernate;
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

import java.util.List;

import static junit.framework.TestCase.*;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;

@RunWith(JUnitParamsRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class, UnscheduledAddressesDAOImpl.class})
@SqlGroup({
        @Sql(scripts = "classpath:db/UnscheduledAddressesDAO.sql", executionPhase = BEFORE_TEST_METHOD),
        @Sql(scripts = "classpath:db/CleanTables.sql", executionPhase = AFTER_TEST_METHOD)
})
public class UnscheduledAddressesDAOImplTest {

    @ClassRule
    public static final SpringClassRule SCR = new SpringClassRule();

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    @Autowired
    IUnscheduledAddressesDAO unscheduledAddressesDAO;

    @Test
    @Parameters({
            "true, false, 11, 1, FETCH, address",
            "false, true, 9, 2, FETCH, utility",
            "true, true, 9, 2, FETCH, address, utility",
    })
    public void testGetByUtilityId(boolean isAddress, boolean isUtility, int size, Long utilityId, EntityGraphType type, String... attributeGraph) {
        List<UnscheduledAddresses> ua = unscheduledAddressesDAO.getByUtilityId(utilityId, type, attributeGraph);

        assertNotNull("The list of unscheduled addresses is null", ua);
        assertFalse("The list of unscheduled addresses is empty", ua.isEmpty());
        assertEquals("Size is not equals", ua.size(), size);
        assertEquals("The 'Address' graph is not initialized", Hibernate.isInitialized(ua.get(0).getAddress()), isAddress);
        assertEquals("The 'Utility' graph is not initialized", Hibernate.isInitialized(ua.get(0).getUtility()), isUtility);
    }

    @Test
    public void testGetAddressListByUtilityId() {
        List<Address> addresses = unscheduledAddressesDAO.getAddressListByUtilityId(1L);

        assertNotNull("The list of unscheduled addresses is null", addresses);
        assertFalse("The list of unscheduled addresses is empty", addresses.isEmpty());
        assertEquals("Size is not equals", addresses.size(), 11);
    }

    @Test
    public void testGetObjects() {
        List<Address> addresses = unscheduledAddressesDAO.getObjects(1L, 0);

        assertNotNull("The list of unscheduled addresses is null", addresses);
        assertFalse("The list of unscheduled addresses is empty", addresses.isEmpty());
        assertEquals("Size is not equals", addresses.size(), 10);
    }

    @Test
    public void testGetPages() {
        Long pageSize = unscheduledAddressesDAO.getPages(1L);

        assertNotNull("The page size is null", pageSize);
        assertEquals("Size is not equals", pageSize, new Long(2L));
    }

}
