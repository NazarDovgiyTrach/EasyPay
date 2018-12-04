package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.ICounterDAO;
import com.softserveinc.ch067.easypay.model.Counter;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.jdbc.SqlGroup;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class, CounterDAOImpl.class})
@SqlGroup({
        @Sql(scripts = "classpath:db/DebtDAO.sql", executionPhase = BEFORE_TEST_METHOD),
        @Sql(scripts = "classpath:db/CleanTables.sql", executionPhase = AFTER_TEST_METHOD)
})
public class CounterDAOImplTest {
    private static LocalDate TEST_DATE = LocalDate.now().withMonth(8).withDayOfMonth(20);
    private static int MAX_RESULTS = 200;
    private static Long ADDRESS_ID = 4L;
    private static Long USER_ID = 102L;
    private static List<Long> EXPECTED_FROM_GET_FIXED_COUNTERS_FOR_REGULAR_PAY = Arrays.asList(1L, 5L, 9L, 11L, 13L);
    private static List<Long> EXPECTED_FROM_GET_COUNTERS_BY_ADDRESS_ID = Arrays.asList(1L, 2L);
    private static List<Long> EXPECTED_FROM_GET_ALL_BY_USER_ID = Arrays.asList(5L, 6L, 7L, 8L);

    @Autowired
    private ICounterDAO counterDAO;

    private List<Long> getCountersIds(List<Counter> counters) {
        List<Long> result = new ArrayList<>();
        for (Counter counter : counters) {
            result.add(counter.getId());
        }
        return result;
    }

    @Test
    public void getFixedCounterForRegularPay() {
        List<Long> actual = getCountersIds(counterDAO.getFixedCounterForRegularPay(TEST_DATE, MAX_RESULTS));
        assertThat(EXPECTED_FROM_GET_FIXED_COUNTERS_FOR_REGULAR_PAY, Matchers.containsInAnyOrder(actual.toArray()));
    }

    @Test
    public void getCountersByAddressId() {
        List<Long> actual = getCountersIds(counterDAO.getCountersByAddressId(ADDRESS_ID));
        assertThat(EXPECTED_FROM_GET_COUNTERS_BY_ADDRESS_ID, Matchers.containsInAnyOrder(actual.toArray()));
    }

    @Test
    public void getAllByUserId() {
        List<Long> actual = getCountersIds(counterDAO.getAllByUserId(USER_ID));
        assertThat(EXPECTED_FROM_GET_ALL_BY_USER_ID, Matchers.containsInAnyOrder(actual.toArray()));
    }

}
