package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.UtilityDTO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;
import org.springframework.core.io.Resource;

import java.util.List;
import java.util.Set;

public interface IUtilityService {
    void create(Utility utility);

    Utility getById(long id);

    Utility getById(long id, boolean withAddress);

    Utility getById(long id, boolean withAddress, boolean withManager);

    Utility getById(long id, boolean withAddress, boolean withManager, boolean withCounters);

    Utility getById(long id, boolean withAddress, boolean withManager, boolean withCounters, boolean withInspectors);

    void update(Utility utility);

    void delete(Utility utility);

    List<Utility> getAll();

    List<Utility> getAll( boolean withAddress);

    List<Utility> getAll( boolean withAddress, boolean withManager);

    List<Utility> getAll( boolean withAddress, boolean withManager, boolean withCounters);

    List<Utility> getAll( boolean withAddress, boolean withManager, boolean withCounters, boolean withInspectors);

    void setActive(Long id, boolean isActive);

    List<User> getAllInspectors(User user);

    List<Address> getAllAddressesByInspectors(User manager);

    void addInspector(User manager, Long[] id);

    void addLogotype(Long id, byte[] logotype);

    Resource getDefaultUtilityLogo();

    Utility getUtilityByManager(User manager, boolean withAddress, boolean withCounters, boolean withInspectors);

    void deleteInspector(User manager, Long idInspector);

    String getUtilityNameByCounter(Counter counter);

    Utility getUtilityByCounter(Counter counter);

    Utility getUtilityByInspector(User inspector);

    Utility getByCounters(Set<Counter> counters);

    List<Utility> getAllByAddress(Long addressId);

    Long getPages();

    List<Utility> getObjects(int firstResult);

    void changeName(UtilityDTO dto);

    void changeManager(UtilityDTO dto);

    Utility getUtilityByInspectorWithCounters(User inspector);

    String[] checkAttributes(boolean withAddress, boolean withManager, boolean withCounters, boolean withInspectors);
}
