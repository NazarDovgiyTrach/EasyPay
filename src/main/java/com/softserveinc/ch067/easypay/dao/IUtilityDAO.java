package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;

import java.util.List;
import java.util.Set;

public interface IUtilityDAO {

    Utility getById(Long id);

    void create(Utility o);

    void update(Utility o);

    void delete(Utility utility);

    List<Utility> getAll();

    List<Utility> getAll(String...attr);

    Utility getUtilityByUser(User user, String... attr);

    void deleteInspector(Long idUtility, Long idInspector);

    String getUtilityNameByCounter(Counter counter);

    Utility getUtilityByCounter(Counter counter);

    Utility getUtilityByInspector(User inspector);

    List<Utility> getAllByAddress(Long addressId);

    Long getPages();

    List<Utility> getObjects(int firstResult);

    Utility getById(Long id,String...attr);

    Utility getUtilityByInspectorWithCounters(User inspector);
}
