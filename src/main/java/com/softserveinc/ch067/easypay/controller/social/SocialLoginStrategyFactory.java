package com.softserveinc.ch067.easypay.controller.social;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class SocialLoginStrategyFactory {

    @Autowired
    private FacebookLogin facebookLogin;
    @Autowired
    private GoogleLogin googleLogin;

    public ISocialStrategy getSocialLoginStrategy(String clientId){
        switch (clientId) {
            case "google": return googleLogin;
            case "facebook": return facebookLogin;
            default: throw new IllegalArgumentException("No such client id!");
        }
    }
}
