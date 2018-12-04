package com.softserveinc.ch067.easypay.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;
import org.springframework.context.annotation.Lazy;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDate;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "debts")
@NamedQueries({
        @NamedQuery(
                name = "Debt.getDebtByUtilityAndAddress",
                query = "SELECT d FROM Counter c JOIN c.debt d " +
                        "WHERE d.utility.id = :utilityId AND c.address.id = :addressId"
        ),
        @NamedQuery(
                name = "Debt.updateLastCounterReminderSend",
                query = "update Debt d set d.lastCounterReminderSend = :today where d.id in :idList"
        ),
        @NamedQuery(
                name = "Debt.updateLastDebtReminderSend",
                query = "update Debt d set d.lastDebtReminderSend = :today where d.id in :idList"
        ),
        @NamedQuery(
                name = "Debt.getUnpaid",
                query = "select  " +
                        "new com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO(" +
                        "c.debt.utility.name," +
                        "c.user.name,c.user.surname,c.user.email,c.user.phoneNumber," +
                        "c.debt.value,c.debt.id," +
                        "c.address) " +
                        "from Counter c  where " +
                        "c.debt.value > 0 and c.active = true and c.address.isActive = true and " +
                        "(c.debt.lastPaid is null  or c.debt.lastPaid < :beforeLastPaid ) and " +
                        "(c.debt.lastDebtReminderSend is null or c.debt.lastDebtReminderSend <:lastDebtReminderSend ) " +
                        "order by c.debt.value desc"
        ),
        @NamedQuery(
                name = "Debt.getDebtWithUnreportedCounters",
                query = "select new com.softserveinc.ch067.easypay.dto.DebtInfoForMailingDTO(" +
                        "c.debt.utility.name," +
                        "c.user.name,c.user.surname,c.user.email,c.user.phoneNumber," +
                        "c.debt.value,c.debt.id," +
                        "c.address)" +
                        "from Counter c where " +
                        "c.fixed = false and c.active = true and c.address.isActive = true and " +
                        "(c.lastUpdated is null  or c.lastUpdated < :beforeDate ) and " +
                        "(c.debt.lastCounterReminderSend is null or c.debt.lastCounterReminderSend <:lastReminderSend )" +
                        "order by c.lastUpdated desc "
        )
})
public class Debt {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "debt_sequence")
    @SequenceGenerator(name = "debt_sequence", sequenceName = "debt_sequence_item_id_seq", allocationSize = 1, initialValue = 50)
    @Column(name = "id")
    private Long id;

    @Column(name = "value", precision = 10, scale = 2)
    private Double value;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "utility_id")
    private Utility utility;

    @Column(name = "last_debt_reminder_send")
    @Lazy
    private LocalDate lastDebtReminderSend;

    @Column(name = "last_counter_reminder_send")
    @Lazy
    private LocalDate lastCounterReminderSend;

    @Column(name = "last_paid")
    private LocalDate lastPaid;

    public Debt() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Double getValue() {
        return value;
    }

    public void setValue(Double value) {
        this.value = value;
    }

    public Utility getUtility() {
        return utility;
    }

    public void setUtility(Utility utility) {
        this.utility = utility;
    }

    public LocalDate getLastDebtReminderSend() {
        return lastDebtReminderSend;
    }

    public void setLastDebtReminderSend(LocalDate lastDebtReminderSend) {
        this.lastDebtReminderSend = lastDebtReminderSend;
    }

    public LocalDate getLastCounterReminderSend() {
        return lastCounterReminderSend;
    }

    public void setLastCounterReminderSend(LocalDate lastCounterReminderSend) {
        this.lastCounterReminderSend = lastCounterReminderSend;
    }

    public LocalDate getLastPaid() {
        return lastPaid;
    }

    public void setLastPaid(LocalDate lastPaid) {
        this.lastPaid = lastPaid;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Debt debt = (Debt) o;

        if (id != null ? !id.equals(debt.id) : debt.id != null) return false;
        if (value != null ? !value.equals(debt.value) : debt.value != null) return false;
        if (lastDebtReminderSend != null ? !lastDebtReminderSend.equals(debt.lastDebtReminderSend) : debt.lastDebtReminderSend != null)
            return false;
        if (lastCounterReminderSend != null ? !lastCounterReminderSend.equals(debt.lastCounterReminderSend) : debt.lastCounterReminderSend != null)
            return false;
        return lastPaid != null ? lastPaid.equals(debt.lastPaid) : debt.lastPaid == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (value != null ? value.hashCode() : 0);
        result = 31 * result + (lastDebtReminderSend != null ? lastDebtReminderSend.hashCode() : 0);
        result = 31 * result + (lastCounterReminderSend != null ? lastCounterReminderSend.hashCode() : 0);
        result = 31 * result + (lastPaid != null ? lastPaid.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Debt{" +
                "id=" + id +
                ", value=" + value +
                ", utility=" + utility +
                ", lastDebtReminderSend=" + lastDebtReminderSend +
                ", lastCounterReminderSend=" + lastCounterReminderSend +
                ", lastPaid=" + lastPaid +
                '}';
    }
}
