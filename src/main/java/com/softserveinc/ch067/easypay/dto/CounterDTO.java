package com.softserveinc.ch067.easypay.dto;

public class CounterDTO {

    private Long id;
    private Long userId;
    private Long addressId;
    private Long oldValue;
    private Long currentValue;
    private boolean isActive;
    private boolean isFixed;

    public CounterDTO() {
    }

    public CounterDTO(Long id, Long userId, Long addressId, Long oldValue, Long currentValue, boolean isActive, boolean isFixed) {
        this.id = id;
        this.userId = userId;
        this.addressId = addressId;
        this.oldValue = oldValue;
        this.currentValue = currentValue;
        this.isActive = isActive;
        this.isFixed = isFixed;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public long getAddressId() {
        return addressId;
    }

    public void setAddressId(long addressId) {
        this.addressId = addressId;
    }

    public Long getOldValue() {
        return oldValue;
    }

    public void setOldValue(Long oldValue) {
        this.oldValue = oldValue;
    }

    public Long getCurrentValue() {
        return currentValue;
    }

    public void setCurrentValue(Long currentValue) {
        this.currentValue = currentValue;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public boolean isFixed() {
        return isFixed;
    }

    public void setFixed(boolean fixed) {
        isFixed = fixed;
    }


    @Override
    public String toString() {
        return "CounterDTO{" +
                "id=" + id +
                ", userId=" + userId +
                ", addressId=" + addressId +
                ", oldValue=" + oldValue +
                ", currentValue=" + currentValue +
                ", isActive=" + isActive +
                ", isFixed=" + isFixed +
                '}';
    }
}
