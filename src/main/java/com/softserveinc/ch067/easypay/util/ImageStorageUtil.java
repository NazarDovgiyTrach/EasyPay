package com.softserveinc.ch067.easypay.util;



import com.softserveinc.ch067.easypay.dto.GeneratedFileDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Component;

import java.io.*;

@Component
public class ImageStorageUtil {

    @Deprecated
    public boolean saveImage(String uploadDir,String fileName,byte[] fileBytes) throws IOException{
        File locationDir = new File(uploadDir);
        locationDir.mkdirs();
        File file = new File(uploadDir+"//"+fileName);
        GeneratedFileDTO generatedFileDTO = new GeneratedFileDTO();
        generatedFileDTO.setFileName(fileName);
        generatedFileDTO.setFileContent(fileBytes);

        if (file.createNewFile()) {
            try (OutputStream outputStream = new FileOutputStream(file)) {
                outputStream.write(fileBytes);
                return true;
            }
        }
        return false;
    }
    @Deprecated
    public void removeFileIfExist(String uploadDir,String fileName){
        if ((fileName!=null)&&(!fileName.isEmpty())) {
            File file = new File(uploadDir + "//" + fileName);
            if (file.exists()) {
                file.delete();
            }
        }


    }

    public Resource getFileAsResource(String uploadDir,String fileName) throws IOException {
        File file = new File(uploadDir+"//"+fileName);
        return fileToResource(file,fileName);

    }

    public Resource fileToResource(File file, String fileName) throws IOException{
        if (file.exists()) {
            Resource resource = new UrlResource(file.toURI());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            } else {
                throw new IOException(
                        "Could not read file: " + fileName);
            }
        }
        return null;
    }

    public Resource getFileFromResourceFolder(String fileName) throws IOException{
        File file = new File(getClass().getResource(fileName).getFile());
        return fileToResource(file,fileName);
    }




}
