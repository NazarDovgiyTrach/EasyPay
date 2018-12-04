package com.softserveinc.ch067.easypay.dao.impl;

import org.springframework.util.StringUtils;

import javax.persistence.EntityGraph;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceContextType;
import javax.persistence.Subgraph;
import java.lang.reflect.ParameterizedType;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public abstract class CrudDAO<T> {

    private Class<T> tClass;


    protected EntityManager entityManager;

    @PersistenceContext
    public void setEntityManager(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    CrudDAO() {
        this.tClass = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
    }

    public T getById(Long id) {
        return (T) entityManager.find(tClass, id);
    }

    public List<T> getAll() {
        return entityManager.createQuery("from " + tClass.getName()).getResultList();
    }

    public void create(T entity) {
        entityManager.persist(entity);
    }

    public T createWithEntityReturn(T entity) {
        entityManager.persist(entity);
        entityManager.flush();

        return entity;
    }

    public void update(T entity) {
        entityManager.merge(entity);
    }

    public void delete(T entity) {
        entityManager.remove(entityManager.contains(entity) ? entity : entityManager.merge(entity));
    }

    void buildEntityGraph(EntityGraph<T> entityGraph, String[] attributeGraph) {
        List<String> attributePaths = Arrays.asList(attributeGraph);

        Collections.sort(attributePaths);
        Collections.reverse(attributePaths);

        for (String path : attributePaths) {

            if (!path.contains(".")) {
                entityGraph.addAttributeNodes(path);
                continue;
            }

            String[] pathComponents = StringUtils.delimitedListToStringArray(path, ".");
            Subgraph<?> parent = null;

            for (int c = 0; c < pathComponents.length - 1; c++) {
                parent = c == 0 ? entityGraph.addSubgraph(pathComponents[c]) : parent.addSubgraph(pathComponents[c]);
            }

            parent.addAttributeNodes(pathComponents[pathComponents.length - 1]);
        }
    }
}
