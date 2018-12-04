package com.softserveinc.ch067.easypay.dao.impl;

import com.softserveinc.ch067.easypay.dao.IUtilityDAO;
import com.softserveinc.ch067.easypay.model.*;
import org.hibernate.HibernateException;
import org.springframework.stereotype.Repository;
import javax.persistence.criteria.*;
import java.util.Arrays;
import java.util.List;


@Repository
public class UtilityDAOImpl extends PaginationDAO<Utility> implements IUtilityDAO {

    @Override
    public Utility getUtilityByUser(User user, String... attr) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        Arrays.stream(attr).forEach(e -> root.fetch(e));
        query.select(root).where(builder.equal(root.get(Utility_.manager), user));
        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public void deleteInspector(Long idUtility, Long idInspector) {
        Utility utility = entityManager.find(Utility.class, idUtility);
        utility.getInspectors().remove(entityManager.find(User.class, idInspector));
    }

    @Override
    public List<Utility> getAllByAddress(Long addressId) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        root.fetch(Utility_.address);
        root.fetch(Utility_.manager);
        root.fetch(Utility_.inspectors);
        Join<Utility, Counter> joinCounters = root.join(Utility_.counters);
        Join<Counter, Address> joinAddress = joinCounters.join(Counter_.address);
        query.select(root).distinct(true).where(builder.equal(joinAddress.get(Address_.id), addressId));
        return entityManager.createQuery(query).getResultList();

    }

    @Override
    public List<Utility> getObjects(int firstResult) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        root.fetch(Utility_.address);
        root.fetch(Utility_.manager);
        query.select(root);
        return entityManager.createQuery(query).setFirstResult(firstResult).setMaxResults(10).getResultList();

    }

    @Override
    public List<Utility> getAll() {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        root.fetch(Utility_.address);
        root.fetch(Utility_.manager);
        root.fetch(Utility_.counters);
        root.fetch(Utility_.inspectors);
        return entityManager.createQuery(query.select(root).distinct(true)).getResultList();
    }


    public List<Utility> getAll(String... attr) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        Arrays.stream(attr).forEach(e -> root.fetch(e));
        return entityManager.createQuery(query.select(root).distinct(true)).getResultList();
    }

    @Override
    public Utility getById(Long id) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        root.fetch(Utility_.address);
        root.fetch(Utility_.manager);
        root.fetch(Utility_.counters);
        root.fetch(Utility_.inspectors);
        query.select(root).where(builder.equal(root.get(Utility_.id), id));
        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public Utility getById(Long id, String... attr) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Utility> query = builder.createQuery(Utility.class);
        Root<Utility> root = query.from(Utility.class);
        Arrays.stream(attr).forEach(e -> root.fetch(e));
        query.select(root).where(builder.equal(root.get(Utility_.id), id));
        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public String getUtilityNameByCounter(Counter counter) {
        return entityManager.createQuery("SELECT u.name FROM Utility u WHERE :counter IN elements(u.counters)", String.class)
                .setParameter("counter", counter)
                .getSingleResult();
    }

    @Override
    public Utility getUtilityByInspector(User inspector) throws HibernateException {
        return entityManager.createQuery("SELECT u FROM Utility u join fetch u.address a join fetch u.manager m join fetch u.inspectors i WHERE :inspector IN elements(u.inspectors)", Utility.class)
                .setParameter("inspector", inspector)
                .getSingleResult();
    }

    @Override
    public Utility getUtilityByCounter(Counter counter) {
        return entityManager.createQuery("SELECT u FROM Utility u join fetch u.address a join fetch u.manager m WHERE :counter IN elements(u.counters)", Utility.class)
                .setParameter("counter", counter)
                .getSingleResult();
    }
    @Override
    public Utility getUtilityByInspectorWithCounters(User inspector) throws HibernateException {
        return entityManager.createQuery("SELECT u FROM Utility u join fetch u.counters c WHERE :inspector IN elements(u.inspectors)", Utility.class)
                .setParameter("inspector", inspector)
                .getSingleResult();
    }

}




