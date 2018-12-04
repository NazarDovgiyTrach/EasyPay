package com.softserveinc.ch067.easypay.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
@PropertySource("classpath:socialOAuth2.properties")
public class SocialConfig {

    private static List<String> clients = Arrays.asList("facebook", "google");

    @Value("${facebookClientId}")
    private String facebookClientId;
    @Value("${facebookClientSecret}")
    private String facebookClientSecret;
    @Value("${facebookUserInfoUri}")
    private String facebookUserInfoUri;

    @Value("${googleClientId}")
    private String googleClientId;
    @Value("${googleClientSecret}")
    private String googleClientSecret;

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = clients.stream()
                .map(this::getRegistration)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        return new InMemoryClientRegistrationRepository(registrations);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository());
    }

    private ClientRegistration getRegistration(String client) {
        if (client.equals("google") && googleClientId != null) {
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(googleClientId)
                    .clientSecret(googleClientSecret)
                    .build();
        }
        if (client.equals("facebook") && facebookClientId != null) {
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(facebookClientId)
                    .clientSecret(facebookClientSecret)
                    .userInfoUri(facebookUserInfoUri)
                    .build();
        }
        throw  new IllegalArgumentException("No such client!");
    }
}
