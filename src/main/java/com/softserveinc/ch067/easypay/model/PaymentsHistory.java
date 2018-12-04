package com.softserveinc.ch067.easypay.model;

import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;

import javax.persistence.*;
import java.time.LocalDate;

@Entity
@Table(name = "payments_histories")
public class PaymentsHistory {
    @Id
    @SequenceGenerator(name = "payments_history_sequence", sequenceName = "payments_history_sequence_item_id_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "payments_history_sequence")
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    @Column(name = "pay_date", nullable = false)
    private LocalDate payDate;

    @Column(name = "payment_sum", nullable = false)
    private Double paymentSum;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "utility_id", nullable = false)
    private Utility utility;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "address_id", nullable = false)
    private Address address;

    @Column(length = 200)
    private String checkPath;

    @Column(name = "google_drive_file_id")
    private String googleDriveFileId;

    public PaymentsHistory() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LocalDate getPayDate() {
        return payDate;
    }

    public void setPayDate(LocalDate payDate) {
        this.payDate = payDate;
    }

    public Double getPaymentSum() {
        return paymentSum;
    }

    public void setPaymentSum(Double paymentSum) {
        this.paymentSum = paymentSum;
    }

    public Utility getUtility() {
        return utility;
    }

    public void setUtility(Utility utility) {
        this.utility = utility;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public String getCheckPath() {
        return checkPath;
    }

    public void setCheckPath(String checkPath) {
        this.checkPath = checkPath;
    }

    public String getGoogleDriveFileId() {
        return googleDriveFileId;
    }

    public void setGoogleDriveFileId(String googleDriveFileId) {
        this.googleDriveFileId = googleDriveFileId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PaymentsHistory that = (PaymentsHistory) o;

        if (id != null ? !id.equals(that.id) : that.id != null) return false;
        if (payDate != null ? !payDate.equals(that.payDate) : that.payDate != null) return false;
        if (paymentSum != null ? !paymentSum.equals(that.paymentSum) : that.paymentSum != null) return false;
        if (utility != null ? !utility.equals(that.utility) : that.utility != null) return false;
        if (address != null ? !address.equals(that.address) : that.address != null) return false;
        if (checkPath != null ? !checkPath.equals(that.checkPath) : that.checkPath != null) return false;
        return googleDriveFileId != null ? googleDriveFileId.equals(that.googleDriveFileId) : that.googleDriveFileId == null;
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (payDate != null ? payDate.hashCode() : 0);
        result = 31 * result + (paymentSum != null ? paymentSum.hashCode() : 0);
        result = 31 * result + (utility != null ? utility.hashCode() : 0);
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (checkPath != null ? checkPath.hashCode() : 0);
        result = 31 * result + (googleDriveFileId != null ? googleDriveFileId.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "PaymentsHistory{" +
                "id=" + id +
                ", payDate=" + payDate +
                ", paymentSum=" + paymentSum +
                ", utility=" + utility +
                ", checkPath='" + checkPath + '\'' +
                ", googleDriveFileId='" + googleDriveFileId + '\'' +
                '}';
    }
}
