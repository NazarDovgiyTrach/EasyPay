package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.dto.AddressDTO;
import com.softserveinc.ch067.easypay.model.Address;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IAddressService;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@RestController
public class AddressController {

    private final IAddressService addressService;
    private final IUserService userService;

    @Autowired
    public AddressController(IAddressService addressService, IUserService userService) {
        this.addressService = addressService;
        this.userService = userService;
    }

    @GetMapping("/list")
    public List<Address> getAddresses() {
        return addressService.getAll();
    }

    @PostMapping("/add/address")
    public ResponseEntity<Object> addAddress(@RequestBody @Valid AddressDTO addressDTO, @AuthenticationPrincipal User user, BindingResult result) {
        if (result.hasErrors()) {
            return new ResponseEntity<>("Something went wrong!", HttpStatus.BAD_REQUEST);
        } else {
            addressService.addUserAddress(addressDTO, user);
            return new ResponseEntity<>("Everything is good.", HttpStatus.OK);
        }
    }

    @GetMapping("/listById")
    public Set<Address> getAllById(@AuthenticationPrincipal User user) {
        return userService.getAllAddressesByUserId(user.getId());
    }

    @GetMapping("/address/disconnect")
    public void disconnect(@RequestParam(name = "id") Long id, HttpServletResponse response) {
        addressService.disconnect(id);
        try {
            response.sendRedirect("/user/addresses");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/address/connect")
    public void connect(@RequestParam(name = "id") Long id, HttpServletResponse response) {
        addressService.connect(id);
        try {
            response.sendRedirect("/user/addresses");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/utility/add/address")
    public ResponseEntity<Object> addAddress(@RequestBody @Valid AddressDTO addressDTO, BindingResult result) {
        if (result.hasErrors()) {
            return new ResponseEntity<Object>("Something went wrong!", HttpStatus.BAD_REQUEST);
        }
        long id = addressService.addUtilityAddress(addressDTO);
        return new ResponseEntity<Object>(id, HttpStatus.OK);
    }

    @GetMapping("/getAddress")
    public Address getAddress(@RequestParam("id") String id) {
        return addressService.getById(Long.parseLong(id));
    }

    @GetMapping("/user/addresses/get/pages")
    public Long getPages(@AuthenticationPrincipal User user){
        return userService.getPagesForAddresses(user);
    }

    @GetMapping("/user/addresses/pagination/{pageId}")
    public List<Address> getObjects(@PathVariable int pageId, @AuthenticationPrincipal User user) {
        return userService.getObjectsForAddresses(pageId, user);
    }
}
