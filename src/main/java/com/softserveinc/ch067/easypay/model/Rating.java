package com.softserveinc.ch067.easypay.model;

import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;
import org.hibernate.annotations.Where;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.util.List;


@Entity
@Table(name = "rating")
public class Rating {

    @Id
    @SequenceGenerator(name = "rating_sequence", sequenceName = "rating_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "rating_sequence")
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    @OneToOne(cascade = CascadeType.MERGE)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    @NotNull
    private User user;
    @NotNull
    private Double rating;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Double getRating() {
        return rating;
    }

    public void setRating(Double rating) {
        this.rating = rating;
    }


    public Rating(){

    }

    public Rating(User user){
        this.setUser(user);
        this.setRating(0.0);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Rating rating1 = (Rating) o;

        if (id != null ? !id.equals(rating1.id) : rating1.id != null) return false;
        if (!user.equals(rating1.user)) return false;
        return rating.equals(rating1.rating);
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + user.hashCode();
        result = 31 * result + rating.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "Rating{" +
                "id=" + id +
                ", user=" + user +
                ", rating=" + rating +
                '}';
    }
}
