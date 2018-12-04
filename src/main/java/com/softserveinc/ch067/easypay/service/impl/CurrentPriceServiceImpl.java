package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.ICurrentPriceDAO;
import com.softserveinc.ch067.easypay.dto.PriceAddressDTO;
import com.softserveinc.ch067.easypay.dto.PriceDTO;
import com.softserveinc.ch067.easypay.dto.UtilityPriceDTO;
import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.ICurrentPriceService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Transactional
public class CurrentPriceServiceImpl implements ICurrentPriceService {

    private final ICurrentPriceDAO currentPriceDAO;

    private final IUtilityService utilityService;

    private final ModelMapper modelMapper;

    @Autowired
    public CurrentPriceServiceImpl(ICurrentPriceDAO currentPriceDAO,
                                   @Lazy IUtilityService utilityService,
                                   ModelMapper modelMapper) {
        this.currentPriceDAO = currentPriceDAO;
        this.utilityService = utilityService;
        this.modelMapper = modelMapper;
    }

    @Override
    public void updateCurrentPrice(CurrentPrice currentPrice) {
        currentPriceDAO.update(currentPrice);
    }

    @Override
    @Transactional(readOnly = true)
    public CurrentPrice getCurrentPriceForUtilityByUserId(Long userId) {
        return currentPriceDAO.getCurrentPriceForUtilityByUserId(userId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<CurrentPrice> getAll() {
        return currentPriceDAO.getAll();
    }

    @Override
    @Transactional(readOnly = true)
    public Map<LocalDate, Double> getPriceHistoryByUtilityId(Long utilityId, LocalDate startDate, LocalDate targetDate) {
        List<CurrentPrice> currentPriceList = currentPriceDAO.getPriceHistoryByUtilityId(utilityId, startDate, targetDate);

        return currentPriceList.stream()
                .sorted(Comparator.comparing(CurrentPrice::getDate))
                .collect(Collectors.toMap(
                        CurrentPrice::getDate, CurrentPrice::getPrice,
                        (oldValue, newValue) -> newValue,
                        LinkedHashMap::new
                ));
    }

    @Override
    @Transactional(readOnly = true)
    public CurrentPrice getById(Long currentPriceId) { return currentPriceDAO.getById(currentPriceId); }

    @Override
    public void create(CurrentPrice newPrice) {
        currentPriceDAO.create(newPrice);
    }

    @Override
    public Long createWithIdReturn(CurrentPrice currentPrice) {
        return currentPriceDAO.createWithEntityReturn(currentPrice).getCurrentPriceId();
    }

    @Override
    public void createWithUtility(CurrentPrice currentPrice, Utility utility) {
        currentPrice.setUtility(utility);
        currentPrice.setActive(true);
        currentPrice.setPrice(0.1);
        currentPriceDAO.create(currentPrice);
    }

    @Override
    @Transactional(readOnly = true)
    public PriceDTO convertToDTO(CurrentPrice currentPrice) {
        PriceDTO priceDTO = modelMapper.map(currentPrice, PriceDTO.class);
        UtilityPriceDTO utilityPriceDTO = modelMapper.map(currentPrice.getUtility(), UtilityPriceDTO.class);
        PriceAddressDTO priceAddressDTO = new PriceAddressDTO();

        priceAddressDTO.setAddressId(currentPrice.getUtility().getId());
        priceAddressDTO.setCityName(currentPrice.getUtility().getAddress().getCity().getName());
        priceAddressDTO.setStreetName(currentPrice.getUtility().getAddress().getStreet().getName());
        priceAddressDTO.setHouseNumber(currentPrice.getUtility().getAddress().getHouse().getNumber());

        priceDTO.setPriceAddressDTO(priceAddressDTO);
        priceDTO.setUtilityPriceDTO(utilityPriceDTO);

        return priceDTO;
    }

    @Override
    @Transactional(readOnly = true)
    public CurrentPrice convertToEntity(PriceDTO priceDTO) {
        CurrentPrice currentPrice = modelMapper.map(priceDTO, CurrentPrice.class);
        currentPrice.setUtility(utilityService.getById(priceDTO.getUtilityPriceDTO().getUtilityId()));

        return currentPrice;
    }

    @Override
    public void disableCurrent(Long utilityId) {
        currentPriceDAO.disableCurrentPrice(utilityId);
    }

    @Override
    @Transactional(readOnly = true)
    public CurrentPrice getCurrentPriceByUtility(Utility utility) {
        return currentPriceDAO.getCurrentPriceByUtility(utility);
    }
}
