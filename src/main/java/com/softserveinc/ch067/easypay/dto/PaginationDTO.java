package com.softserveinc.ch067.easypay.dto;

import java.util.List;

public abstract class PaginationDTO<T> {

    private Long pageSize;
    private List<T> objects;

    public Long getPageSize() {
        return pageSize;
    }

    public void setPageSize(Long pageSize) {
        this.pageSize = pageSize;
    }

    public List<T> getObjects() {
        return objects;
    }

    public void setObjects(List<T> objects) {
        this.objects = objects;
    }
}
