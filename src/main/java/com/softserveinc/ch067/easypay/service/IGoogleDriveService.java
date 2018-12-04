package com.softserveinc.ch067.easypay.service;

import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.File;

import java.io.OutputStream;

public interface IGoogleDriveService {
    Drive getDriveSource();
    String getFileUrlByFileId(String fileId);
    File createPDFFile(byte[] bytes, String email, String fileName);
    String createPNGFile(byte[] bytes, String folder, String fileName);
    File createFile(String type,byte[] bytes, String folder, String fileName);

    OutputStream exportFileContent(String fileId, String mimeType);
}
