package com.softserveinc.ch067.easypay.dao;

import java.util.List;

public interface IModel<T> {

    List<T> getAll();

    T getById(Long id);

    void create(T t);

    void update(T t);

    void delete(T t);

    T createWithEntityReturn(T t);

}
