package com.softserveinc.ch067.easypay.service;

import com.softserveinc.ch067.easypay.model.User;

public interface IJwtTokenService {
    String generateAndGetEmailToken(String email);
    String parseEmailTokenAndGetEmail(String token);
}
