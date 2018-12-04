package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IUtilityDAO;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.hamcrest.Matchers;
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

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;


@RunWith(JUnitParamsRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class, UtilityDAOImpl.class})
@SqlGroup({
        @Sql(scripts = "classpath:db/DebtDAO.sql", executionPhase = BEFORE_TEST_METHOD),
        @Sql(scripts = "classpath:db/CleanTables.sql", executionPhase = AFTER_TEST_METHOD)
})
public class UtilityDAOImplTest {

    @ClassRule
    public static final SpringClassRule SCR = new SpringClassRule();

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    @Autowired
    private IUtilityDAO utilityDAO;

    private List<Long> getUtilitiesIds(List<Utility> utilities) {
        return utilities.stream().map(u -> u.getId()).collect(Collectors.toList());
    }

    private Object[] parametersToTestGetAll() {
        return new Object[]{
                new Object[]{new Object[]{Arrays.asList(3L, 2L), true, true, true, true}, null},
                new Object[]{new Object[]{Arrays.asList(2L, 3L), true, false, false, false}, "address"},
                new Object[]{new Object[]{Arrays.asList(3L, 2L), true, true, false, false}, "address", "manager"},
                new Object[]{new Object[]{Arrays.asList(3L, 2L), true, true, true, false}, "address", "manager", "counters"},
                new Object[]{new Object[]{Arrays.asList(3L, 2L), true, true, true, true}, "address", "manager", "counters", "inspectors"}
        };
    }

    private Object[] parametersToTestGetById() {
        return new Object[]{
                new Object[]{new Object[]{2L, true, true, true, true}, 2L, null},
                new Object[]{new Object[]{2L, true, false, false, false}, 2L, "address"},
                new Object[]{new Object[]{2L, true, true, false, false}, 2L, "address", "manager"},
                new Object[]{new Object[]{3L, true, true, true, false}, 3L, "address", "manager", "counters"},
                new Object[]{new Object[]{3L, true, true, true, true}, 3L, "address", "manager", "counters", "inspectors"}
        };
    }

    @Test
    public void getUtilityByUser() {
        assertThat(3L, Matchers.equalTo(utilityDAO.getUtilityByUser(new User(106L)).getId()));
    }

    @Test
    public void getAllByAddress() {
        assertThat(Arrays.asList(2L, 3L), containsInAnyOrder(getUtilitiesIds(utilityDAO.getAllByAddress(4L)).toArray()));
    }

    @Test
    public void getObjects() {
        assertThat(Arrays.asList(2L, 3L), containsInAnyOrder(getUtilitiesIds(utilityDAO.getObjects(0)).toArray()));
    }

    @Test
    @Parameters(method = "parametersToTestGetAll")
    public void getAll(Object[] expected, String... attr) {
        List<Utility> list = (attr == null ? utilityDAO.getAll() :
                (attr.length == 1 ? utilityDAO.getAll(attr[0]) :
                        (attr.length == 2 ? utilityDAO.getAll(attr[0], attr[1]) :
                                (attr.length == 3 ? utilityDAO.getAll(attr[0], attr[1], attr[2]) : utilityDAO.getAll(attr[0], attr[1], attr[2], attr[3])))));

        Boolean isAddress = Hibernate.isInitialized(list.get(0).getAddress());
        Boolean isManager = Hibernate.isInitialized(list.get(0).getManager());
        Boolean isCounters = Hibernate.isInitialized(list.get(0).getCounters());
        Boolean isInspectors = Hibernate.isInitialized(list.get(0).getInspectors());
        assertThat(expected, Matchers.equalTo(
                new Object[]{getUtilitiesIds(list), isAddress, isManager, isCounters, isInspectors}));
    }

    @Test
    @Parameters(method = "parametersToTestGetById")
    public void getById(Object[] expected, Long id, String... attr) {
        Utility utility = (attr == null ? utilityDAO.getById(id) :
                (attr.length == 1 ? utilityDAO.getById(id, attr[0]) :
                        (attr.length == 2 ? utilityDAO.getById(id, attr[0], attr[1]) :
                                (attr.length == 3 ? utilityDAO.getById(id, attr[0], attr[1], attr[2]) : utilityDAO.getById(id, attr[0], attr[1], attr[2], attr[3])))));

        Boolean isAddress = Hibernate.isInitialized(utility.getAddress());
        Boolean isManager = Hibernate.isInitialized(utility.getManager());
        Boolean isCounters = Hibernate.isInitialized(utility.getCounters());
        Boolean isInspectors = Hibernate.isInitialized(utility.getInspectors());
        assertThat(expected, Matchers.equalTo(
                new Object[]{utility.getId(), isAddress, isManager, isCounters, isInspectors}));
    }

    @Test
    public void getUtilityByInspector() {
        assertThat(2L, Matchers.equalTo(utilityDAO.getUtilityByInspector(new User(109L)).getId()));
    }

    @Test
    public void getUtilityByCounter() {
        assertThat(2L, Matchers.equalTo(utilityDAO.getUtilityByCounter(new Counter(13L)).getId()));
    }

    @Test
    public void getUtilityByInspectorWithCounters() {
        Utility utility = utilityDAO.getUtilityByInspectorWithCounters(new User(109L));
        assertThat(new Object[]{2L, true}, Matchers.equalTo(new Object[]{utility.getId(), Hibernate.isInitialized(utility.getCounters())}));

    }


}
