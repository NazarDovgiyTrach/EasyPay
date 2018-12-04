package com.softserveinc.ch067.easypay.dao.impl.dataprovider;

import com.softserveinc.ch067.easypay.model.*;

public class AddressTestDataProvider {
    public Object[] getAddressTestList() {
        return new Object[]{
                new Address[]{
                        new Address(
                                new Region("Чернівецька область", null),
                                new City("Чернівці", new Region("Чернівецька область", null), null),
                                new Street("проспект Незалежності", new City("Чернівці", new Region("Чернівецька область", null), null), null),
                                new House("131", new Street("проспект Незалежності", new City("Чернівці", new Region("Чернівецька область", null), null), null), null),
                                new Flat(new House("131", new Street("проспект Незалежності", new City("Чернівці", new Region("Чернівецька область", null), null), null), null), ""), 0, 0, true),
                        new Address(
                                new Region("Chernivtsi", null),
                                new City("Chernivtsi", new Region("Chernivtsi", null), null),
                                new Street("Komarova", new City("Chernivtsi", new Region("Chernivtsi", null), null), null),
                                new House("1", new Street("Komarova", new City("Chernivtsi", new Region("Chernivtsi", null), null), null), null),
                                new Flat(new House("1", new Street("Komarova", new City("Chernivtsi", new Region("Chernivtsi", null), null), null), null), "1"), 0, 0, true),
                }
        };
    }
}
