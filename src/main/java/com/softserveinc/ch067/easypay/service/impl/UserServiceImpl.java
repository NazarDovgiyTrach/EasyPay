package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.additional.ErrorMessages;
import com.softserveinc.ch067.easypay.dao.IAddressDAO;
import com.softserveinc.ch067.easypay.dao.IDebtDAO;
import com.softserveinc.ch067.easypay.dao.IUserDAO;
import com.softserveinc.ch067.easypay.dao.IUtilityDAO;
import com.softserveinc.ch067.easypay.dto.*;
import com.softserveinc.ch067.easypay.exception.InvalidDataException;
import com.softserveinc.ch067.easypay.model.*;
import com.softserveinc.ch067.easypay.response.AuthorizationResponse;
import com.softserveinc.ch067.easypay.response.MessageResponse;
import com.softserveinc.ch067.easypay.response.VerifyUserResponse;
import com.softserveinc.ch067.easypay.service.*;
import com.softserveinc.ch067.easypay.util.ImageStorageUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.io.Resource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.util.*;


@Service
public class UserServiceImpl implements IUserService {

    private final MessageSource messageSource;

    private final ErrorMessages errorMessages;

    private final PasswordEncoder encryption;

    private final IPaymentService paymentService;

    private final IUserDAO userDAO;

    private final PasswordEncoder passwordEncoder;

    private final IUtilityService utilityService;

    private final IScheduleService scheduleService;

    private final IRatingService ratingService;

    private final String avatarUploadDir;

    private final ImageStorageUtil imageStorageUtil;

    private final IGoogleDriveService googleDriveService;

    private final IUtilityDAO utilityDAO;

    private final IDebtDAO debtDAO;

    private final IAddressDAO addressDAO;

    @Autowired
    public UserServiceImpl(IPaymentService paymentService,
                           ErrorMessages errorMessages,
                           @Qualifier("localeMessageSource") MessageSource messageSource,
                           PasswordEncoder encryption,
                           IUserDAO userDAO,
                           PasswordEncoder passwordEncoder,
                           @Qualifier("avatarUploadDir") String avatarUploadDir,
                           @Lazy IUtilityService utilityService,
                           IRatingService ratingService,
                           IScheduleService scheduleService,
                           IGoogleDriveService googleDriveService,
                           ImageStorageUtil imageStorageUtil, IUtilityDAO utilityDAO, IDebtDAO debtDAO, IAddressDAO addressDAO) {
        this.paymentService = paymentService;
        this.errorMessages = errorMessages;
        this.messageSource = messageSource;
        this.encryption = encryption;
        this.userDAO = userDAO;
        this.passwordEncoder = passwordEncoder;
        this.avatarUploadDir = avatarUploadDir;
        this.utilityService = utilityService;
        this.ratingService = ratingService;
        this.scheduleService = scheduleService;
        this.googleDriveService = googleDriveService;
        this.imageStorageUtil = imageStorageUtil;
        this.utilityDAO = utilityDAO;
        this.debtDAO = debtDAO;
        this.addressDAO = addressDAO;
    }


    @Override
    public User getUserByEmail(String email) {
        return userDAO.getUserByEmail(email.toLowerCase());
    }


    public List<User> getUsersByRole(Role role) {
        return userDAO.getUsersByRole(role);
    }

    @Override
    public User getActiveUserByEmail(String email) {
        return userDAO.getActiveUserByEmail(email.toLowerCase());
    }

    @Override
    public List<User> getObjects(int firstResult) {
        return userDAO.getObjects(firstResult);
    }

    @Override
    public Long getPages() {
        return userDAO.getPages();
    }

    @Override
    public void setActive(User user) {
        user.setUserStatus(UserStatus.ACTIVE);
        userDAO.update(user);
    }

    @Override
    public boolean isPasswordValid(String password) {
        return password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{7,}$");
    }

    @Transactional
    @Override
    public void connectUtil(Long userId, Long utilityId, Long addressId) {
        Utility utility = utilityService.getById(utilityId, false, false, true, false);
        User user = getById(userId);
        Address address = addressDAO.getById(addressId);
        Set<Counter> counters = utility.getCounters();
        boolean createNew = true;

        for (Counter counter : counters) {
            if (counter.getAddress().equals(address) && counter.getUser().equals(user)) {
                createNew = false;
                counter.setActive(true);
                break;
            }
        }

        if (createNew) {
            Counter counter = initCounter(address, user, utility);
            counters.add(counter);
        }

        utility.setCounters(counters);
        utilityDAO.update(utility);
    }

    private Counter initCounter(Address address, User user, Utility utility) {
        Counter counter = new Counter();
        counter.setActive(true);
        counter.setFixed(true);
        counter.setOldValue(0L);
        counter.setCurrentValue(0L);
        counter.setAddress(address);
        counter.setUser(user);
        Debt debt = debtDAO.getDebtByUtilityAndAddress(utility.getId(), address.getId());
        if (debt == null) {
            debt = new Debt();
            debt.setValue(0d);
            debt.setUtility(utility);
            debtDAO.create(debt);

        }
        counter.setDebt(debt);
        return counter;
    }

    @Transactional
    @Override
    public void disconnectUtil(Long userId, Long utilityId, Long addressId) {
        Utility utility = utilityService.getById(utilityId, false, false, true, false);
        User user = getById(userId);
        Address address = addressDAO.getById(addressId);
        Set<Counter> counters = utility.getCounters();
        for (Counter counter : counters) {
            if (counter.getUser().equals(user) && counter.getAddress().equals(address)) {
                counter.setActive(false);
            }
        }
        utility.setCounters(counters);
        utilityDAO.update(utility);
    }

    @Override
    @Transactional
    public User createSocialUser(User user) {
        userDAO.create(user);
        return user;
    }

    @Override
    public User buildSocialUser(SocialUserAttributesDTO socialUserAttributesDTO) {
        User user = new User(socialUserAttributesDTO.getFirstName(), socialUserAttributesDTO.getLastName(),
                socialUserAttributesDTO.getAvatar(), socialUserAttributesDTO.getEmail(), null,
                Role.FINISH_SOCIAL_REGISTRATION, null, LocalDate.now(), null,
                UserStatus.ACTIVE, null);
        String stripeCustomerId = paymentService.createCustomer(user);
        user.setStripeCustomerId(stripeCustomerId);
        return user;
    }

    @Override
    @Transactional
    public void updatePhoneAndSetUserRole(String phoneNumber, Long userId) {
        userDAO.updatePhoneAndSetUserRole(phoneNumber, userId);
    }

    @Override
    public Long getPages(User user) {
        return null;
    }

    @Override
    public Set<Utility> connectedUtilities(Long id) {
        return userDAO.getConnectedUtilities(id);
    }

    @Override
    public void call(CallDTO callDTO, Long id) {
        Utility utility = utilityService.getById(callDTO.getUtilityId());
        Address address = new Address();
        LocalDate localDate = callDTO.getDate();

        Timestamp date = Timestamp.valueOf(localDate.atStartOfDay());
        for (Counter counter : utility.getCounters()) {
            if (counter.getUser().getId().equals(id)) {
                address = counter.getAddress();
            }
        }
        scheduleService.addScheduleItemForCall(utility, date, address);
    }

    @Transactional
    @Override
    public void setLastLoginToUserWithEmail(String email) {
        userDAO.setLastLoginToUserWithEmail(email);
    }

    @Override
    public Set<User> getUsersByAddress(Address address) {
        List<User> allUsers = userDAO.getAll();
        Set<User> users = new HashSet<>();
        for (User user : allUsers) {
            if (user.getAddresses().contains(address)) {
                users.add(user);
            }
        }
        return users;
    }

    @Override
    public UserRatingDTO constructUserRatingDTO(RatingListItem ratingListItem) {
        User user = ratingListItem.getRatedUser();
        UserRatingDTO userRatingDTO = new UserRatingDTO();
        userRatingDTO.setId(user.getId());
        userRatingDTO.setName(user.getName());
        userRatingDTO.setSurname(user.getSurname());
        userRatingDTO.setRating(ratingService.getRatingByUserId(user.getId()).getRating());
        userRatingDTO.setRaterRatingValue(ratingListItem.getRatingValue());
        if (user.getRole().equals(Role.INSPECTOR)) {
            userRatingDTO.setUtilityName(utilityService.getUtilityByInspector(user).getName());
        } else
            userRatingDTO.setUtilityName("");

        return userRatingDTO;
    }

    @Override
    public AuthorizationResponse determineUserStatus(User user, Locale locale) {
        switch (user.getUserStatus()) {
            case NOT_ACTIVE:
                return new AuthorizationResponse(UserStatus.NOT_ACTIVE, messageSource.getMessage("notActiveUser", null, locale));
            case BANNED:
                return new AuthorizationResponse(UserStatus.BANNED, messageSource.getMessage("accountIsBanned", null, locale));
            case REGISTERED_BY_ADMIN:
                return new AuthorizationResponse(UserStatus.REGISTERED_BY_ADMIN, messageSource.getMessage("registeredByAdmin", null, locale));
            default:
                return new AuthorizationResponse(UserStatus.BANNED, messageSource.getMessage("default", null, locale));
        }
    }

    @Override
    public MessageResponse createMessage(String message) {
        return new MessageResponse(message);
    }

    @Override
    public VerifyUserResponse verifyUser(UserValidationDTO user, BindingResult result, Locale locale) {
        Map<String, String> messages = errorMessages.buildResponse(user, result, locale);
        return new VerifyUserResponse(messages);
    }

    @Override
    public VerifyUserResponse verifyUser(ContinueUserRegistrationDTO user, BindingResult result, Locale locale) {
        Map<String, String> messages = errorMessages.buildResponse(user, result, locale);
        return new VerifyUserResponse(messages);
    }

    @Override
    public VerifyUserResponse verifyUser(RegisterUserDTO user, BindingResult result, Locale locale) {
        Map<String, String> messages = errorMessages.buildResponse(user, result, locale);
        return new VerifyUserResponse(messages);
    }

    @Override
    public List<User> getAllFreeInspectors() {
        List<Utility> utilities = utilityService.getAll();
        List<User> allInspectors = getUsersByRole(Role.INSPECTOR);
        ArrayList<User> freeInspectors = new ArrayList<>();
        boolean isFree;
        for (User inspector : allInspectors) {
            isFree = true;
            for (Utility utility : utilities) {
                if (utility.getInspectors().contains(inspector)) {
                    isFree = false;
                    break;
                }
            }
            if (isFree) {
                freeInspectors.add(inspector);
            }
        }
        return freeInspectors;
    }


    @Override
    public Set<Utility> getPayments(User user) {
        Set<Utility> utilities = connectedUtilities(user.getId());
        Set<Counter> counters;
        for (Utility utility : utilities) {
            counters = new HashSet<>();
            for (Counter counter : utility.getCounters()) {
                if (counter.getUser().getId().equals(user.getId()) && counter.isActive()) {
                    counters.add(counter);
                }
            }
            utility.setCounters(counters);
        }
        return utilities;
    }

    @Override
    public Set<Utility> getPaymentsByUserAndAddress(Long addressId, User user) {
        return getUtilitiesToPay(addressId, user.getId());
    }

    @Override
    public List<User> getAll() {
        return userDAO.getAll();
    }

    @Override
    public User getById(Long id) {
        return userDAO.getById(id);
    }

    @Override
    @Transactional
    public void create(User user, Role role) {
        user.setRole(role);
        user.setUserStatus(UserStatus.NOT_ACTIVE);
        user.setPassword(encryption.encode(user.getPassword()));
        user.setStripeCustomerId(paymentService.createCustomer(user));
        userDAO.create(user);
    }

    @Override
    @Transactional
    public void create(User user) {
        user.setUserStatus(UserStatus.REGISTERED_BY_ADMIN);
        user.setPassword(encryption.encode(user.getPassword()));
        user.setStripeCustomerId(paymentService.createCustomer(user));
        userDAO.create(user);
    }

    @Override
    @Transactional
    public void update(User user) {
        userDAO.update(user);
    }

    @Override
    @Transactional
    public void update(ContinueUserRegistrationDTO userDTO, String email) {
        User user = getUserByEmail(email);
        user.setSurname(userDTO.getSurname());
        user.setName(userDTO.getName());
        user.setPhoneNumber(userDTO.getPhoneNumber());
        user.setStripeCustomerId(paymentService.createCustomer(user));
        user.setUserStatus(UserStatus.ACTIVE);
        userDAO.update(user);
    }

    @Override
    public void delete(User user) {
        userDAO.delete(user);
    }

    @Override
    public List<User> getAllBesidesAuthorized(Long id) {
        return userDAO.getAllBesidesAuthorized(id);
    }


    @Override
    public List<User> getAllActiveBesidesAuthorized(Long id) {
        return userDAO.getAllActiveBesidesAuthorized(id);
    }


    @Override
    public List<User> getAllFreeManagers(Role role) {
        List<User> users = new ArrayList<>();
        List<User> managers = userDAO.getUsersByRole(role);
        for (Utility utility : utilityService.getAll()) {
            users.add(utility.getManager());
        }
        managers.removeAll(users);
        return managers;
    }

    @Override
    public boolean isEmailUnique(String email) {
        return userDAO.isEmailUnique(email);
    }


    @Override
    @Transactional
    public User updateUserInfo(String email, UserDataDTO userDataDTO, NewPasswordDTO newPasswordDTO,
                               byte[] newAvatarPng) throws InvalidDataException, IOException {
        User user = userDAO.getUserByEmail(email);
        user.setName(userDataDTO.getName());
        user.setSurname(userDataDTO.getSurname());
        user.setPhoneNumber(userDataDTO.getPhoneNumber());
        if (newPasswordDTO != null) {
            if (!passwordEncoder.matches(newPasswordDTO.getOldPassword(), user.getPassword())) {
                throw new InvalidDataException("incorrectPassword");
            }
            user.setPassword(passwordEncoder.encode(newPasswordDTO.getNewPassword()));
        }
        if (newAvatarPng != null) {
            String fileName = UUID.randomUUID().toString() + ".png";
            String fileIdOnGoogleDrive = googleDriveService.createPNGFile(newAvatarPng, avatarUploadDir, fileName);
            user.setAvatar(fileIdOnGoogleDrive);
        }
        userDAO.update(user);
        return user;
    }

    @Override
    public Resource getDefaultUserAvatar() {
        try {
            return imageStorageUtil.getFileFromResourceFolder("/image/default.png");
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Set<Counter> getCountersByConnectedUtilityAndAddress(Utility utility, Long addressId, Long userId) {
        Set<Counter> counters = new HashSet<>();
        for (Counter counter : utility.getCounters())
            if (counter.getUser().getId().equals(userId) && counter.getAddress().getId().equals(addressId))
                counters.add(counter);
        return counters;
    }

    @Override
    public Long getPagesForAddresses(User user) {
        return userDAO.getPagesForAddresses(user);
    }

    @Override
    public List<Address> getObjectsForAddresses(int pageId, User user) {
        return userDAO.getObjectsForAddresses(pageId, user);
    }

    @Override
    public Long getPages(Long id) {
        String extraCondition = "WHERE t.id NOT IN (" + id + ") AND t.userStatus = '" +
                UserStatus.ACTIVE.toString() + "' OR t.userStatus = '" + UserStatus.BANNED.toString() + "'";
        return userDAO.getPages(extraCondition);
    }

    @Override
    public List<Address> getObjects(int pageId, User user) {
        return null;
    }

    @Override
    public String generatePassword() {
        List<String> charCategories = new ArrayList<>();
        charCategories.add("abcdefghijklmnopqrstuvwxyz");
        charCategories.add("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        charCategories.add("0123456789");
        Random random = new Random(System.nanoTime());
        StringBuilder password = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            String charCategory = charCategories.get(random.nextInt(charCategories.size()));
            int position = random.nextInt(charCategory.length());
            password.append(charCategory.charAt(position));
        }
        return new String(password);
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.REQUIRES_NEW)
    public List<User> getObjects(int firstResult, Long id) {
        return userDAO.getObjects(firstResult, id);
    }

    @Override
    @Transactional(readOnly = true)
    public Long getPages(Utility utility) {
        return userDAO.getPages(utility);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getObjects(int pageId, Utility utility) {
        int firstResult = (pageId - 1) * 10;
        return userDAO.getObjects(firstResult, utility);
    }

    @Override
    public String encodePassword(String password) {
        return encryption.encode(password);
    }

    @Override
    public Set<Utility> getUtilitiesToPay(Long addressId, Long userId) {
        return userDAO.getUtilitiesToPay(addressId, userId);
    }

    @Override
    public Set<Address> getAllAddressesByUserId(Long id) {
        return userDAO.getAllAddressesByUserId(id);
    }

    @Override
    @Transactional
    public void update(UpdateUserDTO userDTO) {
        User user = userDAO.getById(userDTO.getId());
        user.setUserStatus(userDTO.getStatus());
        user.setRole(userDTO.getRole());
        userDAO.update(user);
    }
}
