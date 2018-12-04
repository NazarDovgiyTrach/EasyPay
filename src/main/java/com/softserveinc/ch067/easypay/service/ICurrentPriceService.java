package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.PriceDTO;
import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.Utility;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

public interface ICurrentPriceService {
    void updateCurrentPrice(CurrentPrice currentPrice);
    CurrentPrice getCurrentPriceByUtility(Utility utility);
    CurrentPrice getCurrentPriceForUtilityByUserId(Long userId);
    List<CurrentPrice> getAll();

    Map<LocalDate, Double> getPriceHistoryByUtilityId(Long utilityId, LocalDate startDate, LocalDate targetDate);

    CurrentPrice getById(Long currentPriceId);

    void create(CurrentPrice newPrice);

    void disableCurrent(Long utilityId);

    Long createWithIdReturn(CurrentPrice currentPrice);

    void createWithUtility(CurrentPrice newPrice, Utility utility);

    PriceDTO convertToDTO(CurrentPrice currentPrice);

    CurrentPrice convertToEntity(PriceDTO priceDTO);
}
