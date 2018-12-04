package com.softserveinc.ch067.easypay.dao.impl;

import org.apache.commons.lang3.StringUtils;

import javax.persistence.Query;
import java.lang.reflect.ParameterizedType;
import java.util.List;

public abstract class PaginationDAO<T> extends CrudDAO<T> {

    private Class<T> tClass;
    private final static int MAX_RESULTS = 10;

    PaginationDAO() {
        this.tClass = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
    }

    public List<T> getObjects(int firstResult) {
        return getObjects(firstResult, null);
    }

    public List<T> getObjects(int firstResult, String extendSQL) {
        String ex = StringUtils.isEmpty(extendSQL) ? "" : extendSQL;
        Query query = entityManager.createQuery("FROM " + tClass.getName() + " t " + ex);
        query.setFirstResult(firstResult);
        query.setMaxResults(MAX_RESULTS);
        return query.getResultList();
    }

    public Long getPages() {
        return getPages(null);
    }

    public Long getPages(String extendSQL) {
        String ex = StringUtils.isEmpty(extendSQL) ? "" : extendSQL;
        Query query = entityManager.createQuery("SELECT count(t.id) FROM " + tClass.getName() + " t " + ex);
        Long count = (Long) query.getSingleResult();
        return (long) Math.ceil((double) count / MAX_RESULTS);
    }
}