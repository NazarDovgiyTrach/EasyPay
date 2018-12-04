package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.NewPriceDTO;
import com.softserveinc.ch067.easypay.model.NewPrice;

import java.util.List;

public interface INewPriceService {
    void deleteNewPrice(NewPrice newPrice);
    List<NewPrice> getAll();
    NewPrice getNewPriceByCurrentPriceId(Long currentPriceId);
    void update(NewPrice newPrice);
    NewPriceDTO convertToDTO(NewPrice newPrice);

    NewPrice convertToEntity(NewPriceDTO newPriceDTO);

    void updateCurrentPriceId(Long newCurrentPriceId, Long oldCurrentPriceId);
}
