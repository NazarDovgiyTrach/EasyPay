package com.softserveinc.ch067.easypay.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;

@Configuration
@PropertySource("classpath:gdrive.properties")
public class GoogleDriveConfig {

    @Autowired
    private Environment env;

    @Bean(name = "appName")
    public String getApplicationName(){
        return env.getProperty("application.name");
    }

    @Bean(name = "mainFolderId")
    public String getMainFolderId(){
        return env.getProperty("folder.main.id");
    }
}
