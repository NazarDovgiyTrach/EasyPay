package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.UserPrincipal;
import com.softserveinc.ch067.easypay.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserPrincipalDetailServiceImpl implements UserDetailsService{

    private final IUserService userService;

    @Autowired
    public UserPrincipalDetailServiceImpl(@Lazy IUserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.getUserByEmail(username);
        if(user == null)
            throw new UsernameNotFoundException(username);
        return new UserPrincipal(user);
    }
}
