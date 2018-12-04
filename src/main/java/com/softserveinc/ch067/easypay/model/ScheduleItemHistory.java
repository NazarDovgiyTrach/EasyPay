package com.softserveinc.ch067.easypay.model;

import javax.persistence.*;
import java.sql.Timestamp;
import java.time.LocalDate;

@Entity
@Table(name = "schedule_history")
public class ScheduleItemHistory {
    @Id
    @SequenceGenerator(name = "schedules_history_sequence", sequenceName = "schedules_history_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "schedules_history_sequence")
    @Column(name = "id", nullable = false, unique = true)
    private Long id;


    @OneToOne(cascade = CascadeType.MERGE)
    @JoinColumn(name = "user_id", nullable = false)
    private User inspector;

    @OneToOne(cascade = CascadeType.MERGE)
    @JoinColumn(name = "address_id", nullable = false)
    private Address address;


    @Column(name = "event_date", nullable = false)
    private LocalDate eventDate;


    @Column(name = "submit_date", nullable = false)
    private LocalDate submitDate;

    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(name = "comment")
    private String comment;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getInspector() {
        return inspector;
    }

    public void setInspector(User inspector) {
        this.inspector = inspector;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public LocalDate getEventDate() {
        return eventDate;
    }

    public void setEventDate(LocalDate eventDate) {
        this.eventDate = eventDate;
    }

    public LocalDate getSubmitDate() {
        return submitDate;
    }

    public void setSubmitDate(LocalDate submitDate) {
        this.submitDate = submitDate;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ScheduleItemHistory scheduleItemHistory = (ScheduleItemHistory) o;

        if (!comment.equals(scheduleItemHistory.comment)) return false;
        if (id != null ? !id.equals(scheduleItemHistory.id) : scheduleItemHistory.id != null) return false;
        if (inspector != null ? !inspector.equals(scheduleItemHistory.inspector) : scheduleItemHistory.inspector != null) return false;
        if (address != null ? !address.equals(scheduleItemHistory.address) : scheduleItemHistory.address != null) return false;
        if (eventDate != null ? !eventDate.equals(scheduleItemHistory.eventDate) : scheduleItemHistory.eventDate != null) return false;
        if (submitDate != null ? !submitDate.equals(scheduleItemHistory.submitDate) : scheduleItemHistory.submitDate != null) return false;
        return (status != null ? !status.equals(scheduleItemHistory.status) : scheduleItemHistory.status != null);

    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (comment != null ? comment.hashCode() : 0);
        result = 31 * result + (inspector != null ? inspector.hashCode() : 0);
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (eventDate != null ? eventDate.hashCode() : 0);
        result = 31 * result + (submitDate != null ? submitDate.hashCode() : 0);
        result = 31 * result + (status != null ? status.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "ScheduleItemHistory{" +
                "id=" + id +
                ", inspector=" + inspector +
                ", address=" + address +
                ", eventDate=" + eventDate +
                ", submitDate=" + submitDate +
                ", status=" + status +
                ", comment=" + comment +
                '}';
    }
}
