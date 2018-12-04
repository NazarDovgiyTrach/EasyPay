package com.softserveinc.ch067.easypay.dto;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.util.Objects;


public class UtilityDTO {

    @NotNull(message = "{utilityDTO.error}")
    @Pattern(regexp = "^UPDATE$", message = "{utilityDTO.error}")
    private String keyWord;

    private String utilityId;

    private String manager;

    @Pattern(regexp = "^(([A-Z]+[a-z]*\\s*)+\\\"*([A-Za-z]+\\s*.*)+\\\"*\\s*)|(.)*$", message = "{utility.name.error}")
    private String legalName;

    public String getLegalName() {
        return legalName;
    }

    public void setLegalName(String legalName) {
        this.legalName = legalName;
    }

    public String getManager() {
        return manager;
    }

    public void setManager(String manager) {
        this.manager = manager;
    }

    public String getUtilityId() {
        return utilityId;
    }

    public void setUtilityId(String utilityId) {
        this.utilityId = utilityId;
    }

    public String getKeyWord() {
        return keyWord;
    }

    public void setKeyWord(String keyWord) {
        this.keyWord = keyWord;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UtilityDTO that = (UtilityDTO) o;
        return Objects.equals(keyWord, that.keyWord) &&
                Objects.equals(utilityId, that.utilityId) &&
                Objects.equals(manager, that.manager);
    }

    @Override
    public int hashCode() {

        return Objects.hash(keyWord, utilityId, manager);
    }

    @Override
    public String toString() {
        return "UtilityDTO{" +
                "keyWord='" + keyWord + '\'' +
                ", utilityId='" + utilityId + '\'' +
                ", manager='" + manager + '\'' +
                '}';
    }
}
