package com.softserveinc.ch067.easypay.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:mailing.properties")
public class MailingConfig {

    @Value("${maxMessagePerDay}")
    private Integer maxItemsPerDay;

    @Value("${maxDeptPerQuery}")
    private Integer maxDeptPerQuery;


    @Bean(name = "maxMessagePerDay")
    public Integer getMaxItemsPerDay(){
        return maxItemsPerDay;
    }


    @Bean(name = "maxDeptPerQuery")
    public Integer getMaxDeptPerQuery() {
        return maxDeptPerQuery;
    }
}
