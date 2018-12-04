package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.Utility;

import java.time.LocalDate;
import java.util.List;

public interface ICurrentPriceDAO extends IModel<CurrentPrice> {
    CurrentPrice getCurrentPriceByUtility(Utility utility);
    CurrentPrice getCurrentPriceForUtilityByUserId(Long userId);
    List<CurrentPrice> getPriceHistoryByUtilityId(Long utilityId, LocalDate startDate, LocalDate targetDate);
    void disableCurrentPrice(Long utilityId);
}
