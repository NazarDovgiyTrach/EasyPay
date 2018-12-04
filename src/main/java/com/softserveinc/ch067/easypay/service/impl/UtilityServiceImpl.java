package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.IUtilityDAO;
import com.softserveinc.ch067.easypay.dto.UtilityDTO;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.*;
import com.softserveinc.ch067.easypay.util.ImageStorageUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;


@Service
public class UtilityServiceImpl implements IUtilityService {

    private final IUtilityDAO dao;
    private final IUserService service;
    private final String utilityLogoUploadDir;
    private final IScheduleService scheduleService;
    private final ICounterService counterService;
    private static final int MAX_RESULT = 10;
    private final ImageStorageUtil imageStorageUtil;
    private final IGoogleDriveService googleDriveService;

    @Autowired
    public UtilityServiceImpl(@Lazy IUtilityDAO dao, @Lazy IUserService service,
                              @Qualifier("utilityLogoUploadDir") String utilityLogoUploadDir,
                              @Lazy IScheduleService scheduleService,
                              @Lazy ICounterService counterService,
                              ImageStorageUtil imageStorageUtil, IGoogleDriveService googleDriveService) {
        this.dao = dao;
        this.service = service;
        this.utilityLogoUploadDir = utilityLogoUploadDir;
        this.scheduleService = scheduleService;
        this.counterService = counterService;
        this.imageStorageUtil = imageStorageUtil;
        this.googleDriveService = googleDriveService;
    }


    @Override
    @Transactional
    public void create(Utility utility) {
        dao.create(utility);
    }

    @Override
    @Transactional
    public void update(Utility utility) {
        dao.update(utility);
    }

    @Override
    @Transactional(readOnly = true)
    public Utility getById(long id) {
        return dao.getById(id);
    }

    @Override
    @Transactional
    public void delete(Utility utility) {
        dao.delete(utility);
    }

    @Transactional(readOnly = true)
    public Utility getById(long id, boolean withAddress) {

        return dao.getById(id, checkAttributes(withAddress, false, false, false));
    }

    @Transactional(readOnly = true)
    public Utility getById(long id, boolean withAddress, boolean withManager) {
        return dao.getById(id, checkAttributes(withAddress, withManager, false, false));
    }

    @Transactional(readOnly = true)
    public Utility getById(long id, boolean withAddress, boolean withManager, boolean withCounters) {
        return dao.getById(id, checkAttributes(withAddress, withManager, withCounters, false));
    }

    @Transactional(readOnly = true)
    public Utility getById(long id, boolean withAddress, boolean withManager, boolean withCounters, boolean withInspectors) {
        return dao.getById(id, checkAttributes(withAddress, withManager, withCounters, withInspectors));
    }

    @Override
    @Transactional(readOnly = true)
    public List<Utility> getAll() {
        return dao.getAll();
    }

    @Transactional(readOnly = true)
    public List<Utility> getAll(boolean withAddress) {
        return dao.getAll(checkAttributes(withAddress, false, false, false));
    }

    @Transactional(readOnly = true)
    public List<Utility> getAll(boolean withAddress, boolean withManager) {
        return dao.getAll(checkAttributes(withAddress, withManager, false, false));
    }

    @Transactional(readOnly = true)
    public List<Utility> getAll(boolean withAddress, boolean withManager, boolean withCounters) {
        return dao.getAll(checkAttributes(withAddress, withManager, withCounters, false));
    }

    @Transactional(readOnly = true)
    public List<Utility> getAll(boolean withAddress, boolean withManager, boolean withCounters, boolean withInspectors) {
        return dao.getAll(checkAttributes(withAddress, withManager, withCounters, withInspectors));
    }

    @Transactional(readOnly = true)
    @Override
    public Utility getUtilityByManager(User manager, boolean withAddress, boolean withCounters, boolean withInspectors) {
        return dao.getUtilityByUser(manager, checkAttributes(withAddress, true, withCounters, withInspectors));
    }
    @Transactional(readOnly = true)
    public Utility getUtilityByInspectorWithCounters(User inspector) {
        return dao.getUtilityByInspectorWithCounters(inspector);
    }

    @Transactional(readOnly = true)
    @Override
    public List<User> getAllInspectors(User user) {
        return dao.getUtilityByUser(user, checkAttributes(false, true, false, true)).getInspectors();
    }

    @Transactional(readOnly = true)
    @Override
    public List<Address> getAllAddressesByInspectors(User manager) {
        List<Address> list = new ArrayList<>();
        for (User user : dao.getUtilityByUser(manager, checkAttributes(false, false, false, true)).getInspectors()) {
            list.addAll(user.getAddresses());
        }
        return list;
    }

    @Override
    @Transactional
    public void setActive(Long id, boolean isActive) {
        Utility utility = getById(id,false);
        utility.setActive(isActive);
        dao.update(utility);
    }


    @Override
    @Transactional
    public void addLogotype(Long id, byte[] logotype) {
        Utility utility = getById(id, false);
        if (logotype != null) {
            String fileName = UUID.randomUUID().toString() + ".png";
            String fileId = googleDriveService.createPNGFile(logotype, utilityLogoUploadDir, fileName);
            utility.setLogo(fileId);
        }
        dao.update(utility);
    }


    public Resource getDefaultUtilityLogo() {
        try {
            return imageStorageUtil.getFileFromResourceFolder("/image/logo.png");
        } catch (Exception e) {
            return null;
        }
    }


    @Transactional
    @Override
    public void deleteInspector(User manager, Long idInspector) {
        dao.deleteInspector(dao.getUtilityByUser(manager).getId(), idInspector);
        scheduleService.deleteAllItemsForInspector(idInspector);
    }


    @Override
    @Transactional
    public void addInspector(User manager, Long[] id) {
        Utility utility = dao.getUtilityByUser(manager);
        List<User> list = utility.getInspectors();
        for (Long idInspector : id) {
            list.add(service.getById(idInspector));
        }
        utility.setInspectors(list);
        dao.update(utility);
    }


    @Override
    @Transactional(readOnly = true)
    public String getUtilityNameByCounter(Counter counter) {
        return dao.getUtilityNameByCounter(counter);
    }

    @Override
    @Transactional(readOnly = true)
    public Utility getUtilityByInspector(User inspector) {
        return dao.getUtilityByInspector(inspector);
    }

    @Override
    @Transactional(readOnly = true)
    public Utility getUtilityByCounter(Counter counter) {
        return dao.getUtilityByCounter(counter);
    }

    @Override
    @Transactional(readOnly = true)
    public Utility getByCounters(Set<Counter> counters) {
        List<Utility> utilities = dao.getAll();
        for (Utility utility : utilities) {
            if (utility.getCounters().containsAll(counters))
                return utility;
        }
        return null;
    }


    @Override
    @Transactional(readOnly = true)
    public List<Utility> getAllByAddress(Long addressId) {
        return dao.getAllByAddress(addressId);
    }

    @Override
    @Transactional(readOnly = true)
    public Long getPages() {
        return dao.getPages();
    }


    @Override
    @Transactional(readOnly = true)
    public List<Utility> getObjects(int firstResult) {
        firstResult = (firstResult - 1) * MAX_RESULT;
        return dao.getObjects(firstResult);
    }

    @Override
    @Transactional
    public void changeName(UtilityDTO dto) {
        Utility utility = getById(Long.parseLong(dto.getUtilityId()), false);
        utility.setName(dto.getLegalName());
        dao.update(utility);
    }

    @Transactional
    public void changeManager(UtilityDTO dto) {
        Utility utility = getById(Long.parseLong(dto.getUtilityId()), false);
        utility.setManager(service.getById(Long.parseLong(dto.getManager())));
        dao.update(utility);
    }


    public String[] checkAttributes(boolean withAddress, boolean withManager, boolean withCounters, boolean withInspectors) {
        List<String> list = new ArrayList<>();
        if (withAddress) list.add(Utility_.ADDRESS);
        if (withManager) list.add(Utility_.MANAGER);
        if (withCounters) list.add(Utility_.COUNTERS);
        if (withInspectors) list.add(Utility_.INSPECTORS);
        return list.toArray(new String[0]);
    }
}

