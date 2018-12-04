package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.NewPrice;
import com.softserveinc.ch067.easypay.service.ICurrentPriceService;
import com.softserveinc.ch067.easypay.service.INewPriceService;
import com.softserveinc.ch067.easypay.service.IPlanningPriceUpdateService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Component
@Transactional
public class PlanningPriceUpdateServiceImpl implements IPlanningPriceUpdateService {

    @Autowired
    private ICurrentPriceService currentPriceService;

    @Autowired
    private INewPriceService newPriceService;

    @Autowired
    private IUtilityService utilityService;

    @Override
    public void updatePrice() {
        List<NewPrice> newPriceList = newPriceService.getAll();

        for (NewPrice newPrice : newPriceList) {
            if (isDateOfActivation(newPrice)) {
                CurrentPrice currentPrice = newPrice.getCurrentPrice();
                currentPrice.setDate(newPrice.getActivationDate());
                currentPrice.setPrice(newPrice.getNewPrice());
                currentPrice.setCurrentPriceId(null);

                currentPriceService.disableCurrent(currentPrice.getUtility().getId());
                currentPriceService.create(currentPrice);
                if (!currentPrice.getUtility().getActive())
                    utilityService.setActive(currentPrice.getUtility().getId(), true);
                newPriceService.deleteNewPrice(newPrice);
            }
        }
    }

    private boolean isDateOfActivation(NewPrice newPrice) {
        return LocalDate.now().isEqual(newPrice.getActivationDate()) || newPrice.getActivationDate().isBefore(LocalDate.now());
    }
}
