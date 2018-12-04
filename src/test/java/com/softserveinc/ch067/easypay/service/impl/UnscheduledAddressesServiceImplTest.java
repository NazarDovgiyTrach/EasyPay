package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IUnscheduledAddressesDAO;
import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.UnscheduledAddresses;
import com.softserveinc.ch067.easypay.model.Utility;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.context.ContextConfiguration;

import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class})
public class UnscheduledAddressesServiceImplTest {

    @Mock
    private IUnscheduledAddressesDAO unscheduledAddressesDAO;

    @InjectMocks
    private UnscheduledAddressesServiceImpl unscheduledAddressesService;

    @Before
    public void setMocks() {
        when(unscheduledAddressesDAO.getByUtilityId(1L, EntityGraphType.FETCH, "address")).thenReturn(
                new ArrayList<UnscheduledAddresses>() {{
                    add(new UnscheduledAddresses(new Address(), null));
                }}
        );

        when(unscheduledAddressesDAO.getByUtilityId(1L, EntityGraphType.FETCH, "utility")).thenReturn(
                new ArrayList<UnscheduledAddresses>() {{
                    add(new UnscheduledAddresses(null, new Utility()));
                    add(new UnscheduledAddresses(null, new Utility()));
                }}
        );

        when(unscheduledAddressesDAO.getByUtilityId(1L, EntityGraphType.FETCH, "address", "utility")).thenReturn(
                new ArrayList<UnscheduledAddresses>() {{
                    add(new UnscheduledAddresses(new Address(), new Utility()));
                    add(new UnscheduledAddresses(new Address(), new Utility()));
                    add(new UnscheduledAddresses(new Address(), new Utility()));
                }}
        );
    }

    @Test
    public void testGetByUtility() {
        List<UnscheduledAddresses> list = unscheduledAddressesService.getByUtility(new Utility(1L), true, false);
        assertEquals(1, list.size());
        assertNotNull(list.get(0).getAddress());
        assertNull(list.get(0).getUtility());

        list = unscheduledAddressesService.getByUtility(new Utility(1L), false, true);
        assertEquals(2, list.size());
        assertNull(list.get(0).getAddress());
        assertNotNull(list.get(0).getUtility());

        list = unscheduledAddressesService.getByUtility(new Utility(1L), true, true);
        assertEquals(3, list.size());
        assertNotNull(list.get(0).getAddress());
        assertNotNull(list.get(0).getUtility());

        verify(unscheduledAddressesDAO, times(2)).getByUtilityId(anyLong(), any(), anyString());
    }
}
