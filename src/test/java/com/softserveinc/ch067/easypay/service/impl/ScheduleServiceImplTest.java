package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IScheduleItemDAO;
import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.ScheduleItem;
import com.softserveinc.ch067.easypay.model.User;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.context.ContextConfiguration;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class})
public class ScheduleServiceImplTest {

    @Mock
    private IScheduleItemDAO scheduleItemDAO;

    @InjectMocks
    private ScheduleServiceImpl scheduleService;

    @Before
    public void setMocks() {
        when(scheduleItemDAO.getAll()).thenReturn(new ArrayList<ScheduleItem>() {{
            add(new ScheduleItem());
            add(new ScheduleItem());
        }});

        when(scheduleItemDAO.getById(1L, EntityGraphType.FETCH, "inspector")).thenReturn(
                new ScheduleItem(new User(), null, LocalDate.now(), true)
        );

        when(scheduleItemDAO.getById(1L, EntityGraphType.FETCH, "address")).thenReturn(
                new ScheduleItem(null, new Address(), LocalDate.now(), true)
        );

        when(scheduleItemDAO.getById(1L, EntityGraphType.FETCH, "address", "inspector")).thenReturn(
                new ScheduleItem(new User(), new Address(), LocalDate.now(), true)
        );

        when(scheduleItemDAO.getListByUserId(1L, EntityGraphType.FETCH, "inspector")).thenReturn(
                new ArrayList<ScheduleItem>() {{
                    add(new ScheduleItem(new User(), null, LocalDate.now(), true));
                }}
        );

        when(scheduleItemDAO.getListByUserId(1L, EntityGraphType.FETCH, "address")).thenReturn(
                new ArrayList<ScheduleItem>() {{
                    add(new ScheduleItem(null, new Address(), LocalDate.now(), true));
                    add(new ScheduleItem(null, new Address(), LocalDate.now(), true));
                }}
        );

        when(scheduleItemDAO.getListByUserId(1L, EntityGraphType.FETCH, "address", "inspector")).thenReturn(
                new ArrayList<ScheduleItem>() {{
                    add(new ScheduleItem(new User(), new Address(), LocalDate.now(), true));
                    add(new ScheduleItem(new User(), new Address(), LocalDate.now(), true));
                    add(new ScheduleItem(new User(), new Address(), LocalDate.now(), true));
                }}
        );

        when(scheduleItemDAO.isExist(1L, new ArrayList<Long>() {{
            add(1L);
            add(2L);
            add(3L);
        }})).thenReturn(true);

        when(scheduleItemDAO.isExist(2L, new ArrayList<Long>() {{
            add(1L);
            add(2L);
            add(3L);
        }})).thenReturn(false);

        when(scheduleItemDAO.getCountItemsByUserIdAndDate(1L, LocalDate.now().withDayOfMonth(30))).thenReturn(30L);
        when(scheduleItemDAO.getCountItemsByUserIdAndDate(1L, LocalDate.now().withDayOfMonth(29))).thenReturn(28L);
        when(scheduleItemDAO.getCountItemsByUserIdAndDate(1L, LocalDate.now().withDayOfMonth(26))).thenReturn(20L);
    }

    @Test
    public void testGetAll() {
        assertEquals(2, scheduleService.getAll().size());
        verify(scheduleItemDAO, times(1)).getAll();
    }

    @Test
    public void testGetById() {
        ScheduleItem scheduleItem = scheduleService.getById(1L, false, true);
        assertNotNull(scheduleItem.getInspector());
        assertNull(scheduleItem.getAddress());

        scheduleItem = scheduleService.getById(1L, true, false);
        assertNull(scheduleItem.getInspector());
        assertNotNull(scheduleItem.getAddress());

        scheduleItem = scheduleService.getById(1L, true, true);
        assertNotNull(scheduleItem.getInspector());
        assertNotNull(scheduleItem.getAddress());

        verify(scheduleItemDAO, times(2)).getById(anyLong(), any(), anyString());
    }

    @Test
    public void testGetListByUserId() {
        List<ScheduleItem> list = scheduleService.getListByUserId(1L, false, true);
        Assert.assertEquals(1, list.size());
        assertNotNull(list.get(0).getInspector());
        assertNull(list.get(0).getAddress());

        list = scheduleService.getListByUserId(1L, true, false);
        Assert.assertEquals(2, list.size());
        assertNull(list.get(0).getInspector());
        assertNotNull(list.get(0).getAddress());

        list = scheduleService.getListByUserId(1L, true, true);
        Assert.assertEquals(3, list.size());
        assertNotNull(list.get(0).getInspector());
        assertNotNull(list.get(0).getAddress());

        verify(scheduleItemDAO, times(2)).getListByUserId(anyLong(), any(), anyString());
    }

    @Test
    public void testIsExist() {
        assertTrue(scheduleService.isExist(new Address(1L), new ArrayList<User>() {{
            add(new User(1L));
            add(new User(2L));
            add(new User(3L));
        }}));

        assertFalse(scheduleService.isExist(new Address(2L), new ArrayList<User>() {{
            add(new User(1L));
            add(new User(2L));
            add(new User(3L));
        }}));

        assertFalse(scheduleService.isExist(new Address(1L), new ArrayList<>()));

        verify(scheduleItemDAO, times(2)).isExist(anyLong(), anyList());
    }

    @Test
    public void testGetLeastBusyDayOfInspector() {
        assertEquals(LocalDate.now().withDayOfMonth(28), scheduleService.getLeastBusyDayOfInspector(new User(1L)));
        verify(scheduleItemDAO, atLeastOnce()).getCountItemsByUserIdAndDate(anyLong(), any());
    }
}
