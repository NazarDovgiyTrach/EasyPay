package com.softserveinc.ch067.easypay.controller.social;

import com.softserveinc.ch067.easypay.dto.SocialUserAttributesDTO;

import java.util.Map;
public interface ISocialStrategy {
    void setSocialUserAttributesDTO(Map<String, Object> attributes);
    SocialUserAttributesDTO getSocialUserAttributesDTO();
}
