package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.dto.CallDTO;
import com.softserveinc.ch067.easypay.dto.NewPasswordDTO;
import com.softserveinc.ch067.easypay.dto.SideMenuItemDTO;
import com.softserveinc.ch067.easypay.dto.UserDataDTO;
import com.softserveinc.ch067.easypay.exception.InvalidDataException;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.response.MessageResponse;
import com.softserveinc.ch067.easypay.service.IDebtService;
import com.softserveinc.ch067.easypay.service.IUserService;
import com.softserveinc.ch067.easypay.service.IUtilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.Valid;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
public class UserController {

    private final IUserService userService;
    private final IUtilityService utilityService;
    private final IDebtService debtService;
    private final MessageSource messageSource;
    private final String googleDriveLink;
    private final String apiCORSLink; // api that allow cros origin request

    @Autowired
    public UserController(IUserService userService, IUtilityService utilityService, IDebtService debtService,
                          @Qualifier("localeMessageSource") MessageSource messageSource,
                          @Qualifier("googleDriveLink") String googleDriveLink,
                          @Qualifier("apiCORSLink") String apiCORSLink) {
        this.userService = userService;
        this.utilityService = utilityService;
        this.debtService = debtService;
        this.messageSource = messageSource;
        this.googleDriveLink = googleDriveLink;
        this.apiCORSLink = apiCORSLink;
    }

    @GetMapping("/getByEmail")
    public User getUserByEmail(@RequestParam("email") String email) {
        return userService.getUserByEmail(email);
    }

    @GetMapping("/getAll")
    public List<User> getAllUsers() {
        return userService.getAll();
    }

    @GetMapping("/getAllInspectors")
    public List<User> getAllInspectors() {
        return userService.getUsersByRole(Role.INSPECTOR);
    }

    @GetMapping("/user/connectUtility")
    public RedirectView connectUtility(@RequestParam(name = "utilityId") Long utilityId,
                                       @RequestParam(name = "addressId") Long addressId,
                                       @AuthenticationPrincipal User user) {
        userService.connectUtil(user.getId(), utilityId, addressId);
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("/user/utilities?addressId="+addressId);
        return redirectView;
    }

    @GetMapping("/user/disconnectUtility")
    public RedirectView disconnectUtility(@RequestParam(name = "utilityId") Long utilityId,
                                          @RequestParam(name = "addressId") Long addressId,
                                          @AuthenticationPrincipal User user) {
        userService.disconnectUtil(user.getId(), utilityId, addressId);
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("/user/connected-utilities/");
        return redirectView;
    }

    @GetMapping("/profile/my")
    public User getCurrentUser(Authentication authentication) {
        User userRes = userService.getUserByEmail(authentication.getName());
        if (userRes.getPassword()!=null) {
            userRes.setPassword("");
        }else {
            userRes.setPassword(null);
        }
        return userRes;
    }

    @PostMapping("/profile/update")
    public ResponseEntity updateProfile(Authentication authentication,
                                        @Valid @RequestPart("userDataDTO") UserDataDTO userDataDTO,
                                        Errors userDataDTOErrors,
                                        @Nullable @Valid @RequestPart("newPasswordDTO") NewPasswordDTO newPasswordDTO,
                                        Errors allErrors,
                                        @Nullable @RequestPart("image") MultipartFile image,
                                        Locale locale
    ) {
        try {
            if (allErrors.hasErrors()) {
                return ResponseEntity.badRequest().body(new MessageResponse(messageSource.getMessage("fieldsInvalid",
                        null, locale)));

            }
            byte[] newAvatarPng = null;
            if (image != null) {
                if (!image.getContentType().equals("image/png")) {
                    return ResponseEntity.badRequest().body(Stream.of(messageSource.getMessage("invalidImageSend",
                            null, locale)).collect(Collectors.toMap(k -> "success", v -> v)));
                }
                newAvatarPng = image.getBytes();
            }
            userService.updateUserInfo(authentication.getName(),userDataDTO,newPasswordDTO,newAvatarPng);
            return ResponseEntity.ok().body(new MessageResponse(messageSource.getMessage("profileUpdated",
                    null, locale)));
        }catch (InvalidDataException invalidDataException){
            return ResponseEntity.badRequest().body(new MessageResponse(messageSource.
                            getMessage(invalidDataException.getMessage(),null, locale)));
        } catch (IOException ioException) {
            return ResponseEntity.badRequest().body(new MessageResponse(messageSource.getMessage("invalidImageSend",
                    null, locale)));
        }

    }

    


    @GetMapping("/profile/avatar")
    public ResponseEntity getUserAvatar(Authentication authentication,
                                        @RequestHeader(value = "Origin",defaultValue = "") String origin) {
        User currentUser = userService.getUserByEmail(authentication.getName());
        String avatar = currentUser.getAvatar();
        if ((avatar == null) || avatar.isEmpty()){
            Resource resource = userService.getDefaultUserAvatar();
            return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(resource);
        }

        HttpHeaders headers = new HttpHeaders();
        if (avatar.matches("^[A-Za-z0-9_\\-\\\\.]+$")){ //avatar is file id on google drive
            headers.setLocation(URI.create(apiCORSLink+googleDriveLink+avatar));
        }
        else {  //avatar is url to to image from google or facebook
            headers.setLocation(URI.create(avatar));
        }
        headers.set("Access-Control-Allow-Origin","*");
        headers.set("Origin",origin);
        return new ResponseEntity<>(headers, HttpStatus.MOVED_PERMANENTLY);
    }

    @GetMapping("/getFreeManagers")
    public List<User> getFreeManagers() {
        return userService.getAllFreeManagers(Role.MANAGER);
    }

    @GetMapping("/getUserById")
    public User getUserById(@RequestParam Long id) {
        return userService.getById(id);
    }

    @GetMapping("/get/connected/utilities")
    public Set<Utility> connectedUtilities(@AuthenticationPrincipal User user) {
        return userService.connectedUtilities(user.getId());
    }

    @PostMapping("/call/inspector")
    public void call(@RequestBody CallDTO callDTO, @AuthenticationPrincipal User user) {
        userService.call(callDTO, user.getId());
    }

    @GetMapping("/user/payments")
    public Set<Utility> getPayments(@RequestParam("id") Long id, @AuthenticationPrincipal User user){
        return userService.getUtilitiesToPay(id, user.getId());
    }

    @GetMapping("/user/utility/{id}/debt")
    public Debt getDebtByUtilityAndAddress(@PathVariable("id") Long utilityId,
                                           @RequestParam("addressId") Long addressId){
        return debtService.getDebtByUtilityAndAddress(utilityId, addressId);
    }

    @GetMapping("/user/utility/{id}/counters")
    public Set<Counter> getCountersByConnectedUtility(@PathVariable("id") Long utilityId,
                                                      @RequestParam("addressId") Long addressId,
                                                      @AuthenticationPrincipal User user){
        Utility utility = utilityService.getById(utilityId);
        return userService.getCountersByConnectedUtilityAndAddress(utility, addressId, user.getId());
    }

    @GetMapping("/roles")
    public Role[] getRoles() {
        return Role.names();
    }
}