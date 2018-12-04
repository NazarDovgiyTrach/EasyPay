package com.softserveinc.ch067.easypay.dto;

public class SideMenuItemDTO {

    private String label;
    private String icon;
    private String reference;

    public SideMenuItemDTO(String label, String icon, String reference) {
        this.label = label;
        this.icon = icon;
        this.reference = reference;
    }

    public SideMenuItemDTO(String label, String reference) {
        this.label = label;
        this.reference = reference;
    }

    public SideMenuItemDTO() {
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public String getReference() {
        return reference;
    }

    public void setReference(String reference) {
        this.reference = reference;
    }
}
