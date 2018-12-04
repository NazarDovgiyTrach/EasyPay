package com.softserveinc.ch067.easypay.model;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.Objects;

@Entity
@Table(name = "schedules")
@NamedQueries({
        @NamedQuery(
                name = "ScheduleItem.getById",
                query = "SELECT s FROM ScheduleItem s " +
                        "WHERE s.id = :id"
        ),
        @NamedQuery(
                name = "ScheduleItem.getByInspectorId",
                query = "SELECT s FROM ScheduleItem s " +
                        "WHERE s.inspector.id = :inspectorId " +
                        "ORDER BY s.eventDate DESC"
        ),
        @NamedQuery(
                name = "ScheduleItem.getOverdueItems",
                query = "SELECT s FROM ScheduleItem s " +
                        "WHERE s.eventDate < CURRENT_DATE"
        ),
        @NamedQuery(
                name = "ScheduleItem.getCountByAddressAndInspectorId",
                query = "SELECT COUNT(s) FROM ScheduleItem s " +
                        "WHERE s.address.id = :id AND s.isRepeat = true AND s.inspector.id IN :inspectors_id"
        ),
        @NamedQuery(
                name = "ScheduleItem.getCountItemsByUserIdAndDate",
                query = "SELECT COUNT(s) FROM ScheduleItem s " +
                        "WHERE s.inspector.id = :id AND s.eventDate = :date"
        )
})
public class ScheduleItem {
    @Id
    @SequenceGenerator(name = "schedules_sequence", sequenceName = "schedules_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "schedules_sequence")
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User inspector;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id", nullable = false)
    private Address address;

    @Column(name = "event_date", nullable = false)
    private LocalDate eventDate;

    @Column(name = "is_repeat", nullable = false)
    private Boolean isRepeat;

    public ScheduleItem() {
    }

    public ScheduleItem(User inspector, Address address, LocalDate eventDate, Boolean isRepeat) {
        this.inspector = inspector;
        this.address = address;
        this.eventDate = eventDate;
        this.isRepeat = isRepeat;
    }

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

    public Boolean getRepeat() {
        return isRepeat;
    }

    public void setRepeat(Boolean repeat) {
        isRepeat = repeat;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScheduleItem that = (ScheduleItem) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(inspector, that.inspector) &&
                Objects.equals(address, that.address) &&
                Objects.equals(eventDate, that.eventDate) &&
                Objects.equals(isRepeat, that.isRepeat);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, inspector, address, eventDate, isRepeat);
    }

    @Override
    public String toString() {
        return "ScheduleItem{" +
                "id=" + id +
                ", inspector=" + inspector +
                ", address=" + address +
                ", eventDate=" + eventDate +
                ", isRepeat=" + isRepeat +
                '}';
    }

}
