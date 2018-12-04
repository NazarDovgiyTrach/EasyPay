package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IDebtDAO;
import com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO;
import com.softserveinc.ch067.easypay.model.Debt;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.jdbc.SqlGroup;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.AFTER_TEST_METHOD;
import static org.springframework.test.context.jdbc.Sql.ExecutionPhase.BEFORE_TEST_METHOD;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class, DebtDAOImpl.class})
@SqlGroup({
        @Sql(scripts = "classpath:db/DebtDAO.sql", executionPhase = BEFORE_TEST_METHOD),
        @Sql(scripts = "classpath:db/CleanTables.sql", executionPhase = AFTER_TEST_METHOD)
})
public class DebtDAOImplTest {
    private static LocalDate TEST_DATE = LocalDate.now().withYear(2018).withDayOfMonth(12).minusDays(30);
    private static int DAYS_DELAY_AFTER_TEST_DATE = 10;
    private static List<Long> GET_UNPAID_EXPECTED = Arrays.asList(3L, 4L, 5L, 6L, 9L, 10L, 12L);
    private static List<Long> EXISTING_DEBT_IDS_LIST_EXAMPLE = Arrays.asList(1L, 2L);
    private static int MAX_RESULTS = 200;
    private static Long UTILITY_ID = 2L;
    private static Long ADDRESS_ID = 4L;
    private static Long NOT_EXISTING_UTILITY_ID = 0L;
    private static Long NOT_EXISTING_ADDRESS_ID = 0L;
    private static Long ID_EXPECTED_IN_GET_DEBT_BY_ADDRESS_AND_UTILITY = 1L;

    @Autowired
    private IDebtDAO debtDAO;

    private List<Long> getDebtIdFromDebtInfoDTO(List<DebtInfoForMailingDTO> list) {
        List<Long> result = new ArrayList<>();
        for (DebtInfoForMailingDTO debtInfoForMailingDTO : list) {
            result.add(debtInfoForMailingDTO.getDebtId());
        }
        return result;
    }

    @Test
    public void getUnpaid() {
        List<Long> actual = getDebtIdFromDebtInfoDTO(debtDAO.getUnpaid(TEST_DATE, TEST_DATE.plusDays(DAYS_DELAY_AFTER_TEST_DATE), MAX_RESULTS));
        assertThat(GET_UNPAID_EXPECTED, Matchers.containsInAnyOrder(actual.toArray()));
    }

    @Test
    public void getDebtWithUnreportedCounters() {
        List<Long> expected = Arrays.asList(2L, 4L, 6L);
        List<Long> actual = getDebtIdFromDebtInfoDTO(debtDAO.getDebtWithUnreportedCounters(TEST_DATE, TEST_DATE.plusDays(DAYS_DELAY_AFTER_TEST_DATE), MAX_RESULTS));
        assertThat(expected, Matchers.containsInAnyOrder(actual.toArray()));
    }

    @Test
    public void getDebtByUtilityAndAddress_successful() {
        Debt debt = debtDAO.getDebtByUtilityAndAddress(UTILITY_ID, ADDRESS_ID);
        Assert.assertNotNull(debt);
        Assert.assertEquals(ID_EXPECTED_IN_GET_DEBT_BY_ADDRESS_AND_UTILITY, debt.getId());
    }

    @Test
    public void getDebtByUtilityAndAddress_nullReasonAddressNotExist() {
        Debt debt = debtDAO.getDebtByUtilityAndAddress(UTILITY_ID, NOT_EXISTING_ADDRESS_ID);
        Assert.assertNull(debt);
    }

    @Test
    public void getDebtByUtilityAndAddress_nullReasonUtilityNotExist() {
        Debt debt = debtDAO.getDebtByUtilityAndAddress(NOT_EXISTING_UTILITY_ID, NOT_EXISTING_ADDRESS_ID);
        Assert.assertNull(debt);
    }


    @Test
    @Transactional
    public void updateLastDebtReminderSend() {
        debtDAO.updateLastDebtReminderSend(EXISTING_DEBT_IDS_LIST_EXAMPLE);
        List<Debt> debtList = new ArrayList<>();
        for (Long id : EXISTING_DEBT_IDS_LIST_EXAMPLE) {
            debtList.add(debtDAO.getById(id));
        }
        assertThat(debtList, Matchers.everyItem(hasProperty("lastDebtReminderSend", is(LocalDate.now()))));
    }

    @Test
    @Transactional
    public void updateLastCounterReminderSend() {
        debtDAO.updateLastCounterReminderSend(EXISTING_DEBT_IDS_LIST_EXAMPLE);
        List<Debt> debtList = new ArrayList<>();
        for (Long id : EXISTING_DEBT_IDS_LIST_EXAMPLE) {
            debtList.add(debtDAO.getById(id));
        }
        assertThat(debtList, Matchers.everyItem(hasProperty("lastCounterReminderSend", is(LocalDate.now()))));
    }

}
