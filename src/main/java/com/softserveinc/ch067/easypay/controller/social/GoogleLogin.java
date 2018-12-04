package com.softserveinc.ch067.easypay.controller.social;

import com.softserveinc.ch067.easypay.dto.SocialUserAttributesDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@PropertySource("classpath:socialOAuth2.properties")
public class GoogleLogin implements ISocialStrategy {

    @Value("${googleFirstNameAttributeName}")
    private String googleFirstNameAttributeName;
    @Value("${googleLastNameAttributeName}")
    private String googleLastNameAttributeName;
    @Value("${googleAvatarAttributeName}")
    private String googleAvatarAttributeName;
    @Value("${googleEmailAttributeName}")
    private String googleEmailAttributeName;
    private SocialUserAttributesDTO socialUserAttributesDTO = new SocialUserAttributesDTO();

    private GoogleLogin() {}

    @Override
    public void setSocialUserAttributesDTO(Map<String, Object> attributes) {
        socialUserAttributesDTO.setAvatar((String) attributes.get(googleAvatarAttributeName));
        socialUserAttributesDTO.setEmail((String) attributes.get(googleEmailAttributeName));
        socialUserAttributesDTO.setFirstName((String) attributes.get(googleFirstNameAttributeName));
        socialUserAttributesDTO.setLastName((String) attributes.get(googleLastNameAttributeName));
    }

    @Override
    public SocialUserAttributesDTO getSocialUserAttributesDTO() {
        return socialUserAttributesDTO;
    }
}
