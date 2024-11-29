package dev.gustavorh.lms_dev_10.dtos;

import java.time.LocalDateTime;

public class MemberActivityReportDTO {
    private Long memberId;
    private String rut;
    private String fullName;
    private String state;
    private LocalDateTime registrationDate;
    private Integer totalHistoricalLoans;
    private Integer overdueLoans;
    private Integer activeLoans;

    public MemberActivityReportDTO(Long memberId, String rut, String fullName, String state, LocalDateTime registrationDate, Integer totalHistoricalLoans, Integer overdueLoans, Integer activeLoans) {
        this.memberId = memberId;
        this.rut = rut;
        this.fullName = fullName;
        this.state = state;
        this.registrationDate = registrationDate;
        this.totalHistoricalLoans = totalHistoricalLoans;
        this.overdueLoans = overdueLoans;
        this.activeLoans = activeLoans;
    }

    public Long getMemberId() {
        return memberId;
    }

    public void setMemberId(Long memberId) {
        this.memberId = memberId;
    }

    public String getRut() {
        return rut;
    }

    public void setRut(String rut) {
        this.rut = rut;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public LocalDateTime getRegistrationDate() {
        return registrationDate;
    }

    public void setRegistrationDate(LocalDateTime registrationDate) {
        this.registrationDate = registrationDate;
    }

    public Integer getTotalHistoricalLoans() {
        return totalHistoricalLoans;
    }

    public void setTotalHistoricalLoans(Integer totalHistoricalLoans) {
        this.totalHistoricalLoans = totalHistoricalLoans;
    }

    public Integer getOverdueLoans() {
        return overdueLoans;
    }

    public void setOverdueLoans(Integer overdueLoans) {
        this.overdueLoans = overdueLoans;
    }

    public Integer getActiveLoans() {
        return activeLoans;
    }

    public void setActiveLoans(Integer activeLoans) {
        this.activeLoans = activeLoans;
    }
}
