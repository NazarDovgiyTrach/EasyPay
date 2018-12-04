package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.dto.*;
import com.softserveinc.ch067.easypay.exception.InvalidDataException;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.response.AuthorizationResponse;
import com.softserveinc.ch067.easypay.response.MessageResponse;
import com.softserveinc.ch067.easypay.response.VerifyUserResponse;
import org.springframework.core.io.Resource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public interface IUserService {
    List<User> getAll();

    List<User> getAllBesidesAuthorized(Long id);

    List<User> getAllActiveBesidesAuthorized(Long id);

    User getUserByEmail(String email);

    User getById(Long id);

    void create(User user, Role role);

    void create(User user);

    void update(User user);

    void update(ContinueUserRegistrationDTO userDTO, String email);

    void delete(User user);

    boolean isEmailUnique(String email);

    List<User> getUsersByRole(Role role);

    List<User> getAllFreeManagers(Role role);

    User getActiveUserByEmail(String email);

    boolean isPasswordValid(String password);

    User updateUserInfo(String email, UserDataDTO userDataDTO, NewPasswordDTO newPasswordDTO, byte[] newAvatarPng)
            throws InvalidDataException, IOException;

    Set<Utility> getPayments(User user);


    Resource getDefaultUserAvatar();

    void connectUtil(Long userId, Long utilityId, Long addressId);

    VerifyUserResponse verifyUser(ContinueUserRegistrationDTO user, BindingResult result, Locale locale);

    VerifyUserResponse verifyUser(RegisterUserDTO user, BindingResult result, Locale locale);

    List<User> getAllFreeInspectors();

    Set<Utility> connectedUtilities(Long id);

    Set<Counter> getCountersByConnectedUtilityAndAddress(Utility utility, Long addressId, Long userId);

    void call(CallDTO callDTO, Long id);

    void setActive(User user);

    void setLastLoginToUserWithEmail(String email);

    Set<Utility> getPaymentsByUserAndAddress(Long addressId, User user);

    Set<User> getUsersByAddress(Address address);

    UserRatingDTO constructUserRatingDTO(RatingListItem ratingListItem);

    AuthorizationResponse determineUserStatus(User user, Locale locale);

    MessageResponse createMessage(String message);

    VerifyUserResponse verifyUser(UserValidationDTO userDTO, BindingResult result, Locale locale);

    void disconnectUtil(Long userId, Long utilityId, Long addressId);

    List<User> getObjects(int firstResult);

    Long getPages();

    User createSocialUser(User user);

    User buildSocialUser(SocialUserAttributesDTO socialUserAttributesDTO);

    void updatePhoneAndSetUserRole(String phoneNumber, Long userId);

    Long getPages(User user);

    Long getPagesForAddresses(User user);

    List<Address> getObjectsForAddresses(int pageId, User user);

    Long getPages(Long id);

    List<Address> getObjects(int pageId, User user);

    Long getPages(Utility utility);

    List<User> getObjects(int pageId, Utility utility);
    List<User> getObjects(int pageId, Long id);

    String generatePassword();

    String encodePassword(String password);

    Set<Utility> getUtilitiesToPay(Long addressId, Long userId);

    Set<Address> getAllAddressesByUserId(Long id);

    @Transactional
    void update(UpdateUserDTO userDTO);
}
