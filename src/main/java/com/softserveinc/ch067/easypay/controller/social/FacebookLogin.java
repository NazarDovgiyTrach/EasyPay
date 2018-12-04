package com.softserveinc.ch067.easypay.controller.social;

import com.softserveinc.ch067.easypay.dto.SocialUserAttributesDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
@PropertySource("classpath:socialOAuth2.properties")
public class FacebookLogin implements ISocialStrategy {

    @Value("${facebookFirstNameAttributeName}")
    private String facebookFirstNameAttributeName;
    @Value("${facebookLastNameAttributeName}")
    private String facebookLastNameAttributeName;
    @Value("${facebookAvatarAttributeName}")
    private String facebookAvatarAttributeName;
    @Value("${facebookEmailAttributeName}")
    private String facebookEmailAttributeName;
    private SocialUserAttributesDTO socialUserAttributesDTO = new SocialUserAttributesDTO();

    private FacebookLogin() {}

    @Override
    public void setSocialUserAttributesDTO(Map<String, Object> attributes) {
        socialUserAttributesDTO.setAvatar(((LinkedHashMap)((LinkedHashMap) attributes.get(facebookAvatarAttributeName)).get("data")).get("url").toString());
        socialUserAttributesDTO.setEmail((String) attributes.get(facebookEmailAttributeName));
        socialUserAttributesDTO.setFirstName((String) attributes.get(facebookFirstNameAttributeName));
        socialUserAttributesDTO.setLastName((String) attributes.get(facebookLastNameAttributeName));
    }

    @Override
    public SocialUserAttributesDTO getSocialUserAttributesDTO() {
        return socialUserAttributesDTO;
    }
}
