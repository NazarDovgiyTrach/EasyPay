package com.softserveinc.ch067.easypay.model;

import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.Set;

@Entity
@Table(name = "rating_list_item")
public class RatingListItem {

    @Id
    @SequenceGenerator(name = "rating_list_sequence", sequenceName = "rating_list_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "rating_list_sequence")
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false)
    @NotNull
    private User ratedUser;

    @Column(name = "rating_value")
    @NotNull
    private Double ratingValue;

    @OneToOne
    @NotNull
    private User rater;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public Double getRatingValue() {
        return ratingValue;
    }

    public void setRatingValue(Double ratingValue) {
        this.ratingValue = ratingValue;
    }

    public User getRatedUser() {
        return ratedUser;
    }

    public void setRatedUser(User ratedUser) {
        this.ratedUser = ratedUser;
    }

    public User getRater() {
        return rater;
    }

    public void setRater(User rater) {
        this.rater = rater;
    }

    public  RatingListItem(){

    }
    public RatingListItem(User rater, User ratedUser){
        this.rater=rater;
        this.ratedUser=ratedUser;
        this.ratingValue=0.0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RatingListItem that = (RatingListItem) o;

        if (id != null ? !id.equals(that.id) : that.id != null) return false;
        if (!ratedUser.equals(that.ratedUser)) return false;
        if (!ratingValue.equals(that.ratingValue)) return false;
        return rater.equals(that.rater);
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + ratedUser.hashCode();
        result = 31 * result + ratingValue.hashCode();
        result = 31 * result + rater.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "RatingListItem{" +
                "id=" + id +
                ", ratedUser=" + ratedUser +
                ", ratingValue=" + ratingValue +
                ", rater=" + rater +
                '}';
    }
}
