package com.softserveinc.ch067.easypay.service.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.AbstractInputStreamContent;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.FileList;
import com.softserveinc.ch067.easypay.service.IGoogleDriveService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;


import javax.annotation.PostConstruct;
import java.io.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

@Service
public class GoogleDriveServiceImpl implements IGoogleDriveService {
    private final String applicationName;
    private final String mainFolderId;
    private Drive drive;

    private static final String FILE_PDF = "application/pdf";
    private static final String FILE_PNG = "image/png";

    @Autowired
    public GoogleDriveServiceImpl(@Qualifier("appName") String applicationName, @Qualifier("mainFolderId") String mainFolderId) {
        this.applicationName = applicationName;
        this.mainFolderId = mainFolderId;
    }

    @PostConstruct
    public void initialize(){
        GoogleCredential credentials;
        HttpTransport httpTransport;
        JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
        List<String> scopes = Arrays.asList(DriveScopes.DRIVE);

        try (InputStream credentialsFileStream = new FileInputStream(new File(getClass()
                .getResource("/credentials/easypay_credentials.json")
                .getFile().replaceAll("%20", " "))))
        {
            httpTransport = GoogleNetHttpTransport.newTrustedTransport();

            credentials = GoogleCredential
                    .fromStream(credentialsFileStream, httpTransport, jsonFactory)
                    .createScoped(scopes);
        } catch (GeneralSecurityException | IOException e) {
            return;
        }

        drive = new Drive.Builder(httpTransport, jsonFactory, credentials)
                .setApplicationName(applicationName)
                .build();
    }

    @Override
    public String getFileUrlByFileId(String fileId) {
        try {
            com.google.api.services.drive.model.File file = drive.files().get(fileId).setFields("webViewLink").execute();
            return file.getWebViewLink();
        } catch (IOException e) {
            return null;
        }
    }


    @Override
    public String createPNGFile(byte[] bytes, String folder, String fileName) {
        com.google.api.services.drive.model.File file = createFile(FILE_PNG,bytes,folder,fileName);
        if (file == null){
            return null;
        }
        return file.getId();
    }

    @Override
    public com.google.api.services.drive.model.File createPDFFile(byte[] bytes, String email, String fileName) {
        return createFile(FILE_PDF,bytes,email,fileName);
    }

    @Override
    public com.google.api.services.drive.model.File createFile(String type, byte[] bytes, String folder, String fileName) {
        AbstractInputStreamContent uploadStreamContent = new ByteArrayContent(type, bytes);
        com.google.api.services.drive.model.File directoryMetadata = new com.google.api.services.drive.model.File();
        directoryMetadata.setName(folder);
        directoryMetadata.setMimeType("application/vnd.google-apps.folder");
        directoryMetadata.setParents(Arrays.asList(mainFolderId));
        FileList result;
        com.google.api.services.drive.model.File file = null;
        try {
            result = drive.files().list().setQ(" name contains '" + folder + "' AND '" + mainFolderId + "' IN parents").execute();
            com.google.api.services.drive.model.File directory;

            if(result.getFiles().isEmpty()){
                directory = drive.files()
                        .create(directoryMetadata).setFields("id, name")
                        .execute();
            }
            else{
                directory = result.getFiles().get(0);
            }

            com.google.api.services.drive.model.File fileMetadata = new com.google.api.services.drive.model.File();
            fileMetadata.setName(fileName);
            fileMetadata.setParents(Arrays.asList(directory.getId()));


            file = drive.files()
                    .create(fileMetadata, uploadStreamContent)
                    .setFields("id, webContentLink, webViewLink, parents")
                    .execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return file;
    }

    @Override
    public OutputStream exportFileContent(String fileId, String mimeType) {
        return null;
    }

    public Drive getDriveSource() {
        return drive;
    }
}
