package com.softserveinc.ch067.easypay.controller;

import com.softserveinc.ch067.easypay.controller.social.ISocialStrategy;
import com.softserveinc.ch067.easypay.controller.social.SocialLoginStrategyFactory;
import com.softserveinc.ch067.easypay.exception.AccountIsBannedException;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.UserPrincipal;
import com.softserveinc.ch067.easypay.model.UserStatus;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Arrays;

@RestController
public class SocialOAuthController {

    @Autowired
    private IUserService userService;
    @Autowired
    private SocialLoginStrategyFactory socialLoginStrategyFactory;

    @RequestMapping(value = "/social/success")
    public RedirectView userInfo(OAuth2AuthenticationToken token) {
        ISocialStrategy socialStrategy = socialLoginStrategyFactory.getSocialLoginStrategy(
                token.getAuthorizedClientRegistrationId()
        );

        socialStrategy.setSocialUserAttributesDTO(token.getPrincipal().getAttributes());

        User user = userService.getUserByEmail(socialStrategy.getSocialUserAttributesDTO().getEmail());
        if(user != null) {
            if(user.getUserStatus() == UserStatus.BANNED) {
                throw new AccountIsBannedException("Account is banned!");
            }
            changeSecurityContextAuth(user);
            return new RedirectView("/home");
        }
        User newUser = userService.createSocialUser(userService.buildSocialUser(socialStrategy.getSocialUserAttributesDTO()));
        changeSecurityContextAuth(newUser);
        return new RedirectView("/finish-social-registration");
    }

    @PostMapping("/social/registration/finish")
    public ResponseEntity addPhoneNumber(@RequestParam String phoneNumber, @AuthenticationPrincipal User user) {
        userService.updatePhoneAndSetUserRole(phoneNumber, user.getId());
        changeSecurityContextAuth(userService.getById(user.getId()));
        return new ResponseEntity<>(HttpStatus.OK);
    }

    private void changeSecurityContextAuth(User user) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = new UsernamePasswordAuthenticationToken(new UserPrincipal(user),
                null, Arrays.asList(new SimpleGrantedAuthority(user.getRole().toString())));
        securityContext.setAuthentication(authentication);
    }
}
