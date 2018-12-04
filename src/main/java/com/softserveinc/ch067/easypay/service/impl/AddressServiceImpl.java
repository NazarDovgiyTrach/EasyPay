package com.softserveinc.ch067.easypay.service.impl;

import com.peertopark.java.geocalc.DegreeCoordinate;
import com.peertopark.java.geocalc.EarthCalc;
import com.peertopark.java.geocalc.Point;
import com.softserveinc.ch067.easypay.dao.IAddressDAO;
import com.softserveinc.ch067.easypay.dao.IScheduleItemDAO;
import com.softserveinc.ch067.easypay.dao.impl.EntityGraphType;
import com.softserveinc.ch067.easypay.dto.AddressDTO;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class AddressServiceImpl implements IAddressService {
    private final IAddressDAO addressDAO;
    private final IRegionService regionService;
    private final ICityService cityService;
    private final IStreetService streetService;
    private final IHouseService houseService;
    private final IFlatService flatService;
    private final IUserService userService;
    private final IScheduleItemDAO scheduleItemDAO;

    @Autowired
    public AddressServiceImpl(IAddressDAO addressDAO,
                              IRegionService regionService,
                              ICityService cityService,
                              IStreetService streetService,
                              IHouseService houseService,
                              IFlatService flatService,
                              IUserService userService,
                              IScheduleService scheduleService, IScheduleItemDAO scheduleItemDAO) {
        this.addressDAO = addressDAO;
        this.regionService = regionService;
        this.cityService = cityService;
        this.streetService = streetService;
        this.houseService = houseService;
        this.flatService = flatService;
        this.userService = userService;
        this.scheduleItemDAO = scheduleItemDAO;
    }

    @Override
    public List<Address> getAll() {
        return addressDAO.getAll();
    }

    @Transactional
    @Override
    public void save(Address address) {
        addressDAO.create(address);
    }

    @Transactional
    @Override
    public void disconnect(Long id) {
        Address address = addressDAO.getById(id);
        address.setActive(false);
        addressDAO.update(address);
    }

    @Transactional
    @Override
    public void connect(Long id) {
        Address address = addressDAO.getById(id);
        address.setActive(true);
        addressDAO.update(address);
    }

    @Override
    public Address getById(Long id) {
        return addressDAO.getById(id);
    }

    @Override
    public List<Address> getAddressesByInspectorId(Long id) {
        return scheduleItemDAO.getListByUserId(id, EntityGraphType.FETCH, "address")
                .stream()
                .map(ScheduleItem::getAddress)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public void addUserAddress(AddressDTO addressDTO, User auth) {
        Address address = initAddress(addressDTO);
        if (addressIsUniqueness(address)) {
            addressDAO.create(address);
            User user = userService.getById(auth.getId());
            user.getAddresses().add(address);
            userService.update(user);
        }
    }

    @Override
    public Long addUtilityAddress(AddressDTO addressDTO) {
        Address address = initAddress(addressDTO);
        if (addressIsUniqueness(address)) {
            addressDAO.create(address);
            return address.getId();
        }
        return addressDAO.getAddress(address.getRegion(), address.getCity(), address.getStreet(), address.getHouse(), address.getFlat()).getId();
    }
    private Address initAddress(AddressDTO addressDTO) {
        Region region = checkRegion(addressDTO.getRegion());
        City city = checkCity(addressDTO.getLocality(), region);
        Street street = checkStreet(addressDTO.getRoute(), city);
        House house = checkHouse(addressDTO.getStreetNumber(), street);
        Flat flat = checkFlat(addressDTO.getFlat(), house);

        region = regionService.getById(region.getId());
        city = cityService.getById(city.getId());
        street = streetService.getById(street.getId());
        house = houseService.getById(house.getId());
        flat = flatService.getById(flat.getId());

        Address address = new Address();
        address.setActive(true);
        address.setRegion(region);
        address.setCity(city);
        address.setStreet(street);
        address.setHouse(house);
        address.setFlat(flat);
        address.setLat(addressDTO.getLat());
        address.setLng(addressDTO.getLng());
        return address;
    }

    private boolean addressIsUniqueness(Address address) {
        return addressDAO.isUniqueness(address);
    }

    private Flat checkFlat(String name, House house) {
        if (flatService.isUniqueness(name, house.getId())) {
            Flat flat = new Flat();
            flat.setNumber(name);
            flat.setHouse(house);
            flatService.create(flat);
        }
        return flatService.getByNumberAndHouseId(name, house.getId());
    }

    private Street checkStreet(String name, City city) {
        if (streetService.isUniqueness(name, city.getId())) {
            Street street = new Street();
            street.setName(name);
            street.setCity(city);
            streetService.create(street);
        }
        return streetService.getByNameAndCityId(name, city.getId());
    }

    private Region checkRegion(String name) {
        if (regionService.regionUniqueness(name)) {
            Region region = new Region();
            region.setName(name);
            regionService.create(region);
        }

        return regionService.getByName(name);

    }

    private City checkCity(String name, Region region) {
        if (cityService.cityUniqueness(name)) {
            City city = new City();
            city.setName(name);
            city.setRegion(region);
            cityService.create(city);
        }
        return cityService.getByName(name);
    }

    private House checkHouse(String name, Street street) {
        if (houseService.isUniqueness(name, street.getId())) {
            House house = new House();
            house.setNumber(name);
            house.setStreet(street);
            houseService.create(house);
        }
        return houseService.getByNumberAndStreetId(name, street.getId());
    }
}
