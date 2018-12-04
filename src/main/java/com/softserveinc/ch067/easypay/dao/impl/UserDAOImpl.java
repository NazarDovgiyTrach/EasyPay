package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IUserDAO;
import com.softserveinc.ch067.easypay.model.*;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.Criteria;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.NoResultException;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Repository
public class UserDAOImpl extends PaginationDAO<User> implements IUserDAO {

    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        Query query = entityManager.createQuery("select u from User u where u.email = :email", User.class);
        query.setParameter("email", email);
        return (User) query.getResultList().stream().findFirst().orElse(null);
    }


    @Transactional(readOnly = true)
    public boolean isEmailUnique(String email) {
        Query query = entityManager.createQuery("select u.email from User u where u.email = :email", String.class);
        query.setParameter("email", email);
        return query.getResultList().isEmpty();
    }


    @Override
    public User getActiveUserByEmail(String email) {
        Query query = entityManager.createQuery("select u from User u where u.email = :email and u.userStatus = 'ACTIVE'", User.class);
        query.setParameter("email", email);
        return (User) query.getResultList().stream().findFirst().orElse(null);
    }


    @Override
    public List<User> getUsersByRole(Role role) {
        return entityManager.createQuery("select u from User u where u.role =:role", User.class).setParameter("role", role).getResultList();
    }

    @Override
    public void setLastLoginToUserWithEmail(String email) {
        Query query = entityManager.createQuery("UPDATE User user SET user.lastLogin = current_date WHERE user.email =:email");
        query.setParameter("email", email);
        query.executeUpdate();
    }


    @Override
    public List<User> getAllBesidesAuthorized(Long id) {
        Query query = entityManager.createQuery("select u from User u where u.id not in :id order by u.surname", User.class);
        query.setParameter("id", id);
        return query.getResultList();
    }

    @Override
    public List<User> getAllActiveBesidesAuthorized(Long id) {
        Query query = entityManager.createQuery("select u from User u where u.id not in :id and u.userStatus not in :notActive order by u.surname", User.class);
        query.setParameter("id", id);
        query.setParameter("notActive", UserStatus.NOT_ACTIVE);
        return query.getResultList();
    }

    @Override
    public void updatePhoneAndSetUserRole(String phoneNumber, Long userId) {
        Query query = entityManager.createQuery("update User u set u.role = :role, u.phoneNumber = :phoneNumber where u.id = :userId");
        query.setParameter("role", Role.USER);
        query.setParameter("phoneNumber", phoneNumber);
        query.setParameter("userId", userId);
        query.executeUpdate();
    }

    @Override
    public Long getPagesForAddresses(User user) {
        Query query = entityManager.createQuery("SELECT count(a.id) FROM User u join u.addresses a WHERE u.id = "+ user.getId());
        Long count = (Long) query.getSingleResult();
        return (long) Math.ceil((double) count / 5);
    }

    @Override
    public List<Address> getObjectsForAddresses(int firstResult, User user){
        firstResult = (firstResult-1)*5;
        Query query = entityManager.createQuery("select a from User u join u.addresses a where u.id = " +user.getId());
        query.setFirstResult(firstResult);
        query.setMaxResults(5);
        return query.getResultList();
    }

    @Override
    public List<Address> getObjects(int firstResult, User user) {
        return null;
    }

    @Override
    public Long getPages(Utility utility){
        Query query = entityManager.createQuery("select count(i.id) from Utility u join u.inspectors i where u.id="+utility.getId());
       try {
           return (Long) query.getSingleResult()/10;
       } catch (NoResultException e){
           return 1L;
       }

    }
    @Override
    public List<User> getObjects(int firstResult, Utility utility){
        Query query = entityManager.createQuery("select i from Utility u join u.inspectors i where u.id="+utility.getId());
        query.setFirstResult(firstResult);
        query.setMaxResults(10);
        return query.getResultList();
    }

    @Override
    public Set<Utility> getUtilitiesToPay(Long addressId, Long userId) {
        Query query = entityManager.createQuery("select u from Utility u join fetch u.counters c join fetch u.address a join fetch u.manager m where c.user.id =:userId AND c.address.id =:addressId AND c.active = true");
        query.setParameter("userId", userId);
        query.setParameter("addressId", addressId);
        return new HashSet<>(query.getResultList());
    }

    @Override
    public Set<Utility> getConnectedUtilities(Long id) {
        Query query = entityManager.createQuery("select u from Utility u join fetch u.counters c where c.user.id =: userId");
        query.setParameter("userId", id);
        return new HashSet<>(query.getResultList());
    }

    @Override
    public Set<Address> getAllAddressesByUserId(Long id) {
        Query query = entityManager.createQuery("select a from User u join u.addresses a join fetch a.region r join fetch r.cities where u.id =:userId");
        query.setParameter("userId", id);
        return new HashSet<>(query.getResultList());
    }

    public List<User> getObjects(int firstResult, Long id) {
        firstResult = (firstResult - 1) * 10;
        int pageSize = 10;
        CriteriaBuilder criteriaBuilder = entityManager
                .getCriteriaBuilder();
        CriteriaQuery<User> criteriaQuery = criteriaBuilder
                .createQuery(User.class);
        Root<User> from = criteriaQuery.from(User.class);
        CriteriaQuery<User> select = criteriaQuery.select(from)
                .where(from.get("id").in(id).not())
                .where(from.get("userStatus").in(UserStatus.ACTIVE, UserStatus.BANNED))
                .orderBy(criteriaBuilder.asc(from.get("surname")));
        TypedQuery<User> typedQuery = entityManager.createQuery(select);
        typedQuery.setFirstResult(firstResult);
        typedQuery.setMaxResults(pageSize);
        return typedQuery.getResultList();
    }
}
