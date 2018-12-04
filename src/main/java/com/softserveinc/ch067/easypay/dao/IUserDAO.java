package com.softserveinc.ch067.easypay.dao;

import com.softserveinc.ch067.easypay.model.*;

import java.util.List;
import java.util.Set;


public interface IUserDAO extends IModel<User> {
    User getUserByEmail(String email);

    boolean isEmailUnique(String email);

    List<User> getUsersByRole(Role role);

    User getActiveUserByEmail(String email);

    List<User> getAll();

    List getAllBesidesAuthorized(Long id);

    User getById(Long id);

    void create(User user);

    void update(User user);

    void delete(User user);

    void setLastLoginToUserWithEmail(String email);

    List<User> getAllActiveBesidesAuthorized(Long id);

    void updatePhoneAndSetUserRole(String phoneNumber, Long userId);

    Long getPagesForAddresses(User user);

    Long getPages();

    Long getPages(String extraCondition);

    List<Address> getObjectsForAddresses(int firstResult, User user);

    List<User> getObjects(int firstResult);

    List<User> getObjects(int firstResult, String extraCondition);

    List<Address> getObjects(int firstResult, User user);

    Long getPages(Utility utility);

    List<User> getObjects(int firstResult, Utility utility);

    Set<Utility> getUtilitiesToPay(Long addressId, Long userId);

    Set<Utility> getConnectedUtilities(Long id);

    Set<Address> getAllAddressesByUserId(Long id);

    List<User> getObjects(int firstResult, Long id);
}
