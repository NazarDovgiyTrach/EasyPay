package com.softserveinc.ch067.easypay.dto;

import java.util.Arrays;

public class GeneratedFileDTO {

    private String fileId;
    private String fileName;
    private byte[] fileContent;

    public GeneratedFileDTO() {
    }

    public GeneratedFileDTO(String fileId, String fileName, byte[] fileContent) {
        this.fileId = fileId;
        this.fileName = fileName;
        this.fileContent = fileContent;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public byte[] getFileContent() {
        return fileContent;
    }

    public void setFileContent(byte[] fileContent) {
        this.fileContent = fileContent;
    }
}
