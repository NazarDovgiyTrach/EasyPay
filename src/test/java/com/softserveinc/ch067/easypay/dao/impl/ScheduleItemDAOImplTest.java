package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IScheduleItemDAO;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
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

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.*;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;

@RunWith(JUnitParamsRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class, ScheduleItemDAOImpl.class})
@SqlGroup({
        @Sql(scripts = "classpath:db/ScheduleItemDAO.sql", executionPhase = BEFORE_TEST_METHOD),
        @Sql(scripts = "classpath:db/CleanTables.sql", executionPhase = AFTER_TEST_METHOD)
})
public class ScheduleItemDAOImplTest {

    @ClassRule
    public static final SpringClassRule SCR = new SpringClassRule();

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    @Autowired
    private IScheduleItemDAO scheduleItemDAO;

    @Test
    @Parameters({
            "true, false, 1, FETCH, inspector",
            "false, true, 2, FETCH, address",
            "true, true, 3, FETCH, inspector, address",
    })
    public void testGetById(boolean isInspector, boolean isAddress, Long id, EntityGraphType type, String... attributeGraph) {
        ScheduleItem scheduleItem = scheduleItemDAO.getById(id, type, attributeGraph);

        assertNotNull("The schedule item is null", scheduleItem);
        assertEquals("The 'Inspector' graph is not initialized", Hibernate.isInitialized(scheduleItem.getInspector()), isInspector);
        assertEquals("The 'Address' graph is not initialized", Hibernate.isInitialized(scheduleItem.getAddress()), isAddress);
    }

    @Test
    @Parameters({
            "true, false, 5, 1, FETCH, inspector",
            "false, true, 5, 2, FETCH, address",
            "true, true, 5, 3, FETCH, inspector, address",
    })
    public void testGetListByUserId(boolean isInspector, boolean isAddress, int size, Long id, EntityGraphType type, String... attributeGraph) {
        List<ScheduleItem> scheduleItems = scheduleItemDAO.getListByUserId(id, type, attributeGraph);

        assertNotNull("The list of schedule items is null", scheduleItems);
        assertFalse("The list of schedule items is empty", scheduleItems.isEmpty());
        assertEquals("Size is not equals", scheduleItems.size(), size);
        assertEquals("The 'Inspector' graph is not initialized", Hibernate.isInitialized(scheduleItems.get(0).getInspector()), isInspector);
        assertEquals("The 'Address' graph is not initialized", Hibernate.isInitialized(scheduleItems.get(0).getAddress()), isAddress);
    }

    @Test
    public void testGetOverdueItems() {
        List<ScheduleItem> overdue = scheduleItemDAO.getOverdueItems();

        assertNotNull("The list of overdue is null", overdue);
        assertFalse("The list of overdue is empty", overdue.isEmpty());
    }

    @Test
    @Parameters(method = "parametersForIsExist")
    public void testIsExist(Long addressId, List<Long> inspectorsId, boolean isExist) {
        assertEquals(scheduleItemDAO.isExist(addressId, inspectorsId), isExist);
    }

    @Test
    @Parameters({
            "1, 2018-09-10, 0",
            "1, 2018-09-28, 1",
    })
    public void testGetCountItemsByUserIdAndDate(Long id, String date, Long result) {
        assertEquals(scheduleItemDAO.getCountItemsByUserIdAndDate(id, LocalDate.parse(date)), result);
    }

    private Object[] parametersForIsExist() {
        return new Object[]{
                new Object[]{1L, new ArrayList<Long>() {{
                    add(1L);
                    add(2L);
                }}, true},
                new Object[]{6L, new ArrayList<Long>() {{
                    add(3L);
                    add(4L);
                }}, false},
        };
    }
}
