package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dao.INewPriceDAO;
import com.softserveinc.ch067.easypay.dto.NewPriceDTO;
import com.softserveinc.ch067.easypay.model.NewPrice;
import com.softserveinc.ch067.easypay.service.ICurrentPriceService;
import com.softserveinc.ch067.easypay.service.INewPriceService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class NewPriceServiceImpl implements INewPriceService {

    @Autowired
    private INewPriceDAO newPriceDAO;

    @Autowired
    private ModelMapper modelMapper;

    @Autowired
    private ICurrentPriceService currentPriceService;

    @Override
    public void deleteNewPrice(NewPrice newPrice) {
        newPriceDAO.delete(newPrice);
    }

    @Override
    @Transactional(readOnly = true)
    public List<NewPrice> getAll() { return newPriceDAO.getAll(); }

    @Override
    @Transactional(readOnly = true)
    public NewPrice getNewPriceByCurrentPriceId(Long currentPriceId) { return newPriceDAO.getNewPriceByCurrentPriceId(currentPriceId); }

    @Override
    public void update(NewPrice newPrice) { newPriceDAO.update(newPrice); }

    @Override
    public NewPriceDTO convertToDTO(NewPrice newPrice) {
        if (newPrice != null) {
            NewPriceDTO newPriceDTO = modelMapper.map(newPrice, NewPriceDTO.class);
            newPriceDTO.setCurrentPriceId(newPrice.getCurrentPrice().getCurrentPriceId());
            return newPriceDTO;
        }

        return null;
    }

    @Override
    public NewPrice convertToEntity(NewPriceDTO newPriceDTO) {
        NewPrice newPrice = modelMapper.map(newPriceDTO, NewPrice.class);
        newPrice.setCurrentPrice(currentPriceService.getById(newPriceDTO.getCurrentPriceId()));

        return newPrice;
    }

    @Override
    public void updateCurrentPriceId(Long newCurrentPriceId, Long oldCurrentPriceId) { newPriceDAO.updateCurrentPriceId(newCurrentPriceId, oldCurrentPriceId); }
}
