package com.softserveinc.ch067.easypay.controller;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.softserveinc.ch067.easypay.additional.ErrorMessages;
import com.softserveinc.ch067.easypay.dto.UtilityDTO;
import com.softserveinc.ch067.easypay.dto.UtilityDataDTO;
import com.softserveinc.ch067.easypay.model.Counter;
import com.softserveinc.ch067.easypay.model.CurrentPrice;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.Utility;
import com.softserveinc.ch067.easypay.service.IAddressService;
import com.softserveinc.ch067.easypay.service.ICurrentPriceService;
import com.softserveinc.ch067.easypay.service.IUserService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartRequest;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.Valid;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@RestController
public class UtilityController {

    private final IUtilityService utilityService;
    private final IUserService userService;
    private final IAddressService addressService;
    private final ErrorMessages errorMessages;
    private final ICurrentPriceService currentPriceService;
    private final String googleDriveLink;
    private final MessageSource messageSource;
    private final ModelMapper mapper;

    @Autowired
    public UtilityController(IUtilityService utilityService, IUserService userService, IAddressService addressService, ErrorMessages errorMessages, ICurrentPriceService currentPriceService, @Qualifier("googleDriveLink") String googleDriveLink, @Qualifier("localeMessageSource") MessageSource messageSource, ModelMapper mapper) {
        this.utilityService = utilityService;
        this.userService = userService;
        this.addressService = addressService;
        this.errorMessages = errorMessages;
        this.currentPriceService = currentPriceService;
        this.googleDriveLink = googleDriveLink;
        this.messageSource = messageSource;
        this.mapper = mapper;
    }

    @PostMapping("/admin/addUtility")
    public ResponseEntity<Object> addUtility(Locale locale, @Valid @RequestBody Utility utility, BindingResult result) {

        if (result.hasErrors()) {
            return new ResponseEntity<Object>(errorMessages.getErrorMessagesWithKeys(result), HttpStatus.BAD_REQUEST);
        }
        utilityService.create(utility);
        currentPriceService.createWithUtility(new CurrentPrice(), utility);
        return new ResponseEntity<Object>(Stream.of(messageSource.getMessage("utility.add.success", null, locale)).collect(Collectors.toMap(k -> "success", v -> v)), HttpStatus.OK);
    }


    @GetMapping("/getUtilitiesList/{page}")
    public List<UtilityDataDTO> getAllUtilities(@PathVariable int page) {
         return utilityService.getObjects(page).stream().map(u->mapper.map(u,UtilityDataDTO.class)).collect(Collectors.toList());
    }

    @GetMapping("/utility/setActive")
    public RedirectView setActive(@RequestParam("id") long id, @RequestParam("setActive") Boolean isActive, RedirectAttributes attributes) {
        utilityService.setActive(id, isActive);
        return new RedirectView("/admin/utilitiesPage");
    }

    @PostMapping("/admin/changeManager")
    public ResponseEntity<Object> changeManager(@Valid @RequestBody UtilityDTO dto, BindingResult result, Locale locale) {
        if (result.hasErrors()) {
            return new ResponseEntity<Object>(errorMessages.getErrorMessagesWithKeys(result), HttpStatus.BAD_REQUEST);
        }
        utilityService.changeManager(dto);
        return new ResponseEntity<Object>(Stream.of(messageSource.getMessage("utilityDTO.update.success", null, locale)).collect(Collectors.toMap(k -> "success", v -> v)), HttpStatus.OK);
    }


    @GetMapping("/isConnected")
    public boolean getCounters(@RequestParam(name = "id") Long id, @RequestParam(name = "addressId") Long addressId, @AuthenticationPrincipal User user) {
        Set<Counter> counters = utilityService.getById(id).getCounters();
        for (Counter counter : counters) {
            if (counter.getUser().getId() == user.getId() && counter.getAddress().getId() == addressId && counter.isActive()) {
                return false;
            }
        }
        return true;
    }


    @GetMapping("/utilities")
    public List<Utility> getAll() {
        return utilityService.getAll(false, false,false, false);
    }


    @GetMapping("/getUtilityById")
    public Utility getUtilityById(@RequestParam("id") Long id) {
        return utilityService.getById(id);
    }

    @PostMapping("/admin/addLogo")
    public ResponseEntity<Object> updateLogo(MultipartRequest request, Locale locale) throws IOException {
        MultipartFile multipartFileInformation = request.getFile("info");
        TypeReference<HashMap<String, String>> typeRef = new TypeReference<HashMap<String, String>>() {
        };
        HashMap<String, String> map = new ObjectMapper().readValue(multipartFileInformation.getInputStream(), typeRef);
        MultipartFile file = request.getFile("image");
        if (file == null)
            return new ResponseEntity<>(Stream.of(messageSource.getMessage("add.logo.error", null, locale)).collect(Collectors.toMap(k -> "error", v -> v)), HttpStatus.BAD_REQUEST);
        utilityService.addLogotype(Long.parseLong(map.get("utility_id")), file.getBytes());
        return new ResponseEntity<>(Stream.of(messageSource.getMessage("success", null, locale)).collect(Collectors.toMap(k -> "success", v -> v)), HttpStatus.ACCEPTED);

    }

    @GetMapping("/logotype")
    public ResponseEntity getLogotype(@RequestParam("id") Long id) {
        Utility utility = utilityService.getById(id,false);
        String logo = utility.getLogo();
        if ((logo == null) || (logo.isEmpty())) {
            Resource resource = utilityService.getDefaultUtilityLogo();
            return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(resource);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(googleDriveLink + logo));
        return new ResponseEntity<>(headers, HttpStatus.MOVED_PERMANENTLY);

    }


    @PostMapping("/admin/changeName")
    public ResponseEntity<Object> changeName(@Valid @RequestBody UtilityDTO dto, BindingResult result, Locale locale) {
        if (result.hasErrors()) {
            return new ResponseEntity<Object>(errorMessages.getErrorMessagesWithKeys(result), HttpStatus.BAD_REQUEST);
        }
        utilityService.changeName(dto);
        return new ResponseEntity<Object>(Stream.of(messageSource.getMessage("nameChangedSuccess", null, locale)).collect(Collectors.toMap(k -> "success", v -> v)), HttpStatus.OK);

    }

    @GetMapping("/counter/{id}/utilityName")
    String getUtilityNameByCounter(@PathVariable("id") Long id) {
        Counter counter = new Counter();
        counter.setId(id);
        return utilityService.getUtilityNameByCounter(counter);
    }

    @GetMapping("/address/{id}/utilities")
    List<Utility> getUtilitiesByAddress(@PathVariable("id") Long id) {
        return utilityService.getAllByAddress(id);
    }

    @GetMapping("/utilities/get/pages")
    Long getPages() {
        return utilityService.getPages();
    }


}
