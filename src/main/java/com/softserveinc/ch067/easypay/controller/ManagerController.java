package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.additional.ErrorMessages;
import com.softserveinc.ch067.easypay.dto.NewPriceDTO;
import com.softserveinc.ch067.easypay.dto.PriceDTO;
import com.softserveinc.ch067.easypay.dto.PriceHistoryDTO;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * Manager controller implements manager's functionality
 *
 * @author Pervozvanska Oleksandra
 * @author Prokhnitskyi Vlad
 */

@RestController
@RequestMapping("/manager")
public class ManagerController {

    private IUserService userService;
    private ErrorMessages errorMessages;
    private IScheduleHistoryService scheduleHistoryService;
    private IScheduleService scheduleService;
    private ICurrentPriceService currentPriceService;
    private IUtilityService utilityService;
    private INewPriceService newPriceService;

    @Autowired
    public ManagerController(IUserService userService, ErrorMessages errorMessages, IScheduleHistoryService scheduleHistoryService, IScheduleService scheduleService, ICurrentPriceService currentPriceService, IUtilityService utilityService, INewPriceService newPriceService) {
        this.userService = userService;
        this.errorMessages = errorMessages;
        this.scheduleHistoryService = scheduleHistoryService;
        this.scheduleService = scheduleService;
        this.currentPriceService = currentPriceService;
        this.utilityService = utilityService;
        this.newPriceService = newPriceService;
    }

    /**
     * Get manager's utility
     *
     * @param manager authenticated manager
     */

    @GetMapping("/utility/get")
    public Utility getManagerUtility(@AuthenticationPrincipal User manager) {
        return utilityService.getUtilityByManager(manager,true,false,true);
    }

    /**
     * Get inspector that are not added to any utility
     *
     * @return inspectors that are not assigned to any utility
     */

    @GetMapping("/utility/inspectors/get/free")
    public List<User> getFreeInspectors() {
        return userService.getAllFreeInspectors();
    }

    /**
     * Get utility inspectors
     *
     * @param manager authenticated manager
     * @return inspectors list
     */
    @GetMapping("/utility/schedule/inspectors/get/{pageId}")
    public List<User> getAllInspectors(@AuthenticationPrincipal User manager, @PathVariable int pageId) {
        return userService.getObjects(pageId, utilityService.getUtilityByManager(manager,false,false,true));
    }

    @GetMapping("/utility/schedule/inspectors/get/pages")
    public Long getAllUtilityInspectorsPages(@AuthenticationPrincipal User manager) {
        return userService.getPages(utilityService.getUtilityByManager(manager,false,false,true));
    }

    /**
     * Get inspector's name
     *
     * @param userId inspector's id
     * @return inspector’s name
     */
    @GetMapping("/inspector/get/{userId}")
    public User getInspectorName(@PathVariable long userId) {
        return userService.getById(userId);

    }

    /**
     * Add inspector to utility
     *
     * @param id an array of inspectors ids to add to utility
     */
    @PutMapping("/schedule/addInspector")
    public void addInspector(@RequestBody Long[] id) {
        User manager = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        utilityService.addInspector(manager, id);
    }

    /**
     * Delete inspector from utility
     * also delete inspector's schedule
     *
     * @param id id of inspector to delete
     * @return status OK
     */
    @DeleteMapping("/schedule/deleteInspector")
    public ResponseEntity removeScheduleItem(@RequestBody Long id) {
        User manager = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        utilityService.deleteInspector(manager, id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * Get inspector's schedule
     *
     * @param userId inspector's id
     * @return inspector's schedule
     */
    @GetMapping("/schedule/inspectors/{userId}")
    public List<ScheduleItemHistory> getAllSHItemsByInspector(@PathVariable long userId) {
        return scheduleHistoryService.getSHItemsByInspectorId(userId);
    }

    /**
     * Get inspector's schedule history
     * by page
     *
     * @param id inspector's id
     * @return inspector's schedule history for current month
     */
    @GetMapping("/schedule/inspector/{id}/history/current/{pageId}")
    public List<ScheduleItemHistory> getCurrentSHItemsByInspectorId(@PathVariable long id, @PathVariable int pageId) {

        return scheduleHistoryService.getCurrentSHItemsByInspectorId(id, pageId);
    }

    /**
     * Get inspector's schedule history
     * by page
     *
     * @param id inspector's id
     * @return inspector's schedule history for previous month
     */
    @GetMapping("/schedule/inspector/{id}/history/previous/{pageId}")
    public List<ScheduleItemHistory> getPastSHItemsByInspectorId(@PathVariable long id, @PathVariable int pageId) {
        return scheduleHistoryService.getPastSHItemsByInspectorId(id, pageId);
    }


    /**
     * Get inspector's schedule history current month
     *
     * @param id inspector's id
     * @return inspector's schedule history for current month
     */
    @GetMapping("/schedule/inspector/{id}/history/current/")
    public List<ScheduleItemHistory> getAllCurrentSHItemsByInspectorId(@PathVariable long id) {

        return scheduleHistoryService.getCurrentSHItemsByInspectorId(id);
    }

    /**
     * Get whole inspector's schedule history previous month
     *
     * @param id inspector's id
     * @return inspector's schedule history for previous month
     */
    @GetMapping("/schedule/inspector/{id}/history/previous/")
    public List<ScheduleItemHistory> getAllPastSHItemsByInspectorId(@PathVariable long id) {
        return scheduleHistoryService.getPastSHItemsByInspectorId(id);
    }

    /**
     * Count pages for SH current month
     *
     * @param id - inspector's id
     * @return number of pages
     */
    @GetMapping("/schedule/inspector/{id}/history/current/pages")
    public Long getSHCurrentPages(@PathVariable long id) {
        return scheduleHistoryService.getSHCurrentPages(id);
    }

    /**
     * Count pages for SH previous month
     *
     * @param id - inspector's id
     * @return number of pages
     */
    @GetMapping("/schedule/inspector/{id}/history/previous/pages")
    public Long getSHPastPages(@PathVariable long id) {
        return scheduleHistoryService.getSHPastPages(id);
    }

    /**
     * Get current price for the utility
     *
     * @param currentUser currently authenticated user with manager role
     * @return the current price of utility which manager has
     */
    @GetMapping(value = "/utility/price/get", produces = MediaType.APPLICATION_JSON_VALUE)
    public PriceDTO getCurrentPriceForManager(@AuthenticationPrincipal User currentUser) {
        CurrentPrice currentPrice = currentPriceService.getCurrentPriceForUtilityByUserId(currentUser.getId());
        return currentPriceService.convertToDTO(currentPrice);
    }

    /**
     * Update price for the utility
     *
     * @param priceDTO the current price of utility which manager has
     * @param result   object which have errors from hibernate validation
     * @return object which have http status and error messages
     */
    @PutMapping(value = "/utility/price/update", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity updateCurrentPrice(@Valid @RequestBody PriceDTO priceDTO, BindingResult result) {
        if (result.hasErrors())
            return new ResponseEntity<>(errorMessages.getErrorMessages(result), HttpStatus.BAD_REQUEST);

        CurrentPrice currentPrice = currentPriceService.convertToEntity(priceDTO);

        utilityService.update(currentPrice.getUtility());
        currentPriceService.updateCurrentPrice(currentPrice);

        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * Set new price for the utility immediately. Old price add to the price history
     *
     * @param priceDTO new current price for the utility
     * @param result   object which have errors from hibernate validation
     * @return object which have http status and error messages
     */
    @PutMapping(value = "/utility/price/add", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity addCurrentPrice(@Valid @RequestBody PriceDTO priceDTO, BindingResult result) {
        if (result.hasErrors())
            return new ResponseEntity<>(errorMessages.getErrorMessages(result), HttpStatus.BAD_REQUEST);

        CurrentPrice currentPrice = currentPriceService.convertToEntity(priceDTO);
        Long oldCurrentPriceId = currentPrice.getCurrentPriceId();
        currentPrice.setCurrentPriceId(null);

        currentPriceService.disableCurrent(currentPrice.getUtility().getId());
        Long newCurrentPriceId = currentPriceService.createWithIdReturn(currentPrice);
        newPriceService.updateCurrentPriceId(newCurrentPriceId, oldCurrentPriceId);

        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    /**
     * Get data for the price chart changing
     *
     * @param currentUser currently authenticated user with manager role
     * @return prices history in the data transfer object
     */
    @GetMapping(value = "utility/price/chart", produces = MediaType.APPLICATION_JSON_VALUE)
    public PriceHistoryDTO getPriceHistory(@RequestParam(name = "startDate") String startDate,
                                           @RequestParam(name = "targetDate") String targetDate,
                                           @AuthenticationPrincipal User currentUser) {
        Long utilityId = utilityService.getUtilityByManager(currentUser,false,false,false).getId();
        Map<LocalDate, Double> prices = currentPriceService.getPriceHistoryByUtilityId(utilityId, LocalDate.parse(startDate), LocalDate.parse(targetDate));

        PriceHistoryDTO priceHistoryDTO = new PriceHistoryDTO();
        priceHistoryDTO.setPrices(prices);

        return priceHistoryDTO;
    }

    /**
     * @param currentUser currently authenticated user with manager role
     * @return new price of utility
     */
    @GetMapping(value = "/utility/price/new/get", produces = MediaType.APPLICATION_JSON_VALUE)
    public NewPriceDTO getNewPriceByUtilityId(@AuthenticationPrincipal User currentUser) {
        CurrentPrice currentPrice = currentPriceService.getCurrentPriceForUtilityByUserId(currentUser.getId());

        NewPrice newPrice = newPriceService.getNewPriceByCurrentPriceId(currentPrice.getCurrentPriceId());

        return newPriceService.convertToDTO(newPrice);
    }

    /**
     * @param newPriceDTO new price of utility managing current user
     * @param result   object which have errors from hibernate validation
     * @return object which have http status and error messages
     */
    @PutMapping(value = "/utility/price/new/update", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity updateNewPriceActivation(@Valid @RequestBody NewPriceDTO newPriceDTO, BindingResult result) {
        if (result.hasErrors())
            return new ResponseEntity<>(errorMessages.getErrorMessages(result), HttpStatus.BAD_REQUEST);

        newPriceService.update(newPriceService.convertToEntity(newPriceDTO));

        return new ResponseEntity<>(HttpStatus.OK);
    }

    @Deprecated
    @GetMapping("/schedule/inspectors/addresses/get/")
    public List<Address> getAllAddressesByInspectors(@AuthenticationPrincipal User user) {
        Utility utility = utilityService.getUtilityByManager(user,false,true,false);
        return utility.getCounters().stream().map(Counter::getAddress).collect(Collectors.toList());
    }
}
