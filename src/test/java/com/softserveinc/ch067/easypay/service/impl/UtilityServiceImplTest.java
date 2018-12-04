package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IUtilityDAO;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;

import java.util.Arrays;
import java.util.HashSet;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class})
public class UtilityServiceImplTest {

    private static final User INSPECTOR_1 = new User(111L, new HashSet<Address>(Arrays.asList(new Address(51L))));
    private static final User INSPECTOR_2 = new User(112L, new HashSet<Address>(Arrays.asList(new Address(63L))));
    private static final Counter COUNTER_1 = new Counter();
    private static final Counter COUNTER_2 = new Counter();
    private static final String[] ATTRIBUTES = {Utility_.ADDRESS, Utility_.MANAGER, Utility_.COUNTERS, Utility_.INSPECTORS};

    @Mock
    IUtilityDAO dao;

    @InjectMocks
    UtilityServiceImpl utilityService;

    @BeforeClass
    public static void before() {
        COUNTER_1.setId(1L);
        COUNTER_2.setId(2L);
    }

    @Before
    public void setMocks() {
        when(dao.getUtilityByUser(new User(106L), "inspectors"))
                .thenReturn(new Utility(3L, null, null, Arrays.asList(INSPECTOR_1, INSPECTOR_2), null));
        when(dao.getAll()).thenReturn(Arrays.asList(new Utility(1L, null, null, null, new HashSet<Counter>(Arrays.asList(COUNTER_1, COUNTER_2)))));
    }

    @Test
    public void getAllAddressesByInspectors() {
        assertThat(Arrays.asList(51L, 63L),
                equalTo(utilityService.getAllAddressesByInspectors(new User(106L)).stream().map(a -> a.getId()).collect(Collectors.toList())));
        verify(dao, times(1)).getUtilityByUser(new User(106L), "inspectors");
    }

    @Test
    public void getByCounters() {
        assertThat(1L, equalTo(utilityService.getByCounters(new HashSet<Counter>(Arrays.asList(COUNTER_1, COUNTER_2))).getId()));
        verify(dao, times(1)).getAll();
    }

    @Test
    public void checkAttributes() {
        assertThat(ATTRIBUTES, equalTo(utilityService.checkAttributes(true, true, true, true)));
    }
}
