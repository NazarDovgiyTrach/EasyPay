package com.softserveinc.ch067.easypay.dto;

public class UserRatingDTO {

    private String name;
    private String surname;
    private Double rating;
    private Double raterRatingValue;
    private Long id;
    private String utilityName;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public Double getRating() {
        return rating;
    }

    public void setRating(Double rating) {
        this.rating = rating;
    }

    public Double getRaterRatingValue() {
        return raterRatingValue;
    }

    public void setRaterRatingValue(Double raterRatingValue) {
        this.raterRatingValue = raterRatingValue;
    }

    public String getUtilityName() {
        return utilityName;
    }

    public void setUtilityName(String utilityName) {
        this.utilityName = utilityName;
    }
}
