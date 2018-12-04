package com.softserveinc.ch067.easypay.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:upload.properties")
public class FilesUploadConfig {

    @Value("${checksDir}")
    private String checksDir;
    @Value("${resourceHandlerFilesDir}")
    private String resourceHandlerFilesDir;
    @Value("${avatar}")
    private String avatarUploadDir;
    @Value("${logotype}")
    private String utilityLogoUploadDir;
    @Value("${googleDriveLink}")
    private String googleDriveLink;
    @Value("${apiCORSLink}")
    private String apiCORSLink;

    @Bean(name = "checksDir")
    public String getChecksDir() {
        return checksDir;
    }

    @Bean(name = "avatarUploadDir")
    public String getAvatarUploadDir() {
        return avatarUploadDir;
    }

    @Bean(name = "utilityLogoUploadDir")
    public String getUtilityLogoUploadDir() {
        return utilityLogoUploadDir;
    }

    @Bean(name = "resourceHandlerFilesDir")
    public String resourceHandlerFilesDir() {
        return resourceHandlerFilesDir;
    }

    @Bean(name = "googleDriveLink")
    public String getGoogleDriveLink() {
        return googleDriveLink;
    }

    @Bean(name = "apiCORSLink")
    public String getApiCORSLink() {
        return apiCORSLink;
    }
}
