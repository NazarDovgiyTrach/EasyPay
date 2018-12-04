package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.NewPrice;

public interface INewPriceDAO extends IModel<NewPrice> {
    NewPrice getNewPriceByCurrentPriceId (Long currentPriceId);

    void updateCurrentPriceId(Long newCurrentPriceId, Long oldCurrentPriceId);
}
