package com.softserveinc.ch067.easypay.controller.l10n;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.context.MessageSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

@RestController
public class L10nController {
    @Autowired
    @Qualifier("localeMessageSource")
    private MessageSource messageSource;
    @Autowired
    @Qualifier("localesProperties")
    private Properties localesProperties;

    @GetMapping("/getMessages")
    public Map getMessages(Locale locale) {
        return localesProperties.keySet().stream().collect(Collectors.toMap(k->k.toString(),v->messageSource.getMessage(v.toString(),null,locale)));
    }

}
