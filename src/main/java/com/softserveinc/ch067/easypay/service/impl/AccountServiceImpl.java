package com.softserveinc.ch067.easypay.service.impl;

import com.softserveinc.ch067.easypay.dto.*;
import com.softserveinc.ch067.easypay.exception.ConfirmRegistrationJWTInvalidException;
import com.softserveinc.ch067.easypay.exception.PasswordResetJWTInvalidException;
import com.softserveinc.ch067.easypay.model.EmailToken;
import com.softserveinc.ch067.easypay.model.Role;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.model.UserStatus;
import com.softserveinc.ch067.easypay.response.AuthorizationResponse;
import com.softserveinc.ch067.easypay.response.MessageResponse;
import com.softserveinc.ch067.easypay.response.VerifyUserResponse;
import com.softserveinc.ch067.easypay.service.*;
import io.jsonwebtoken.JwtException;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.validation.BindingResult;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.Locale;

@Service
public class AccountServiceImpl implements IAccountService {

    private final ModelMapper modelMapper;
    private final IMailService mailService;
    private final IUserService userService;
    private final IEmailTokenService emailTokenService;
    private final MessageSource messageSource;
    private final AuthenticationManager authenticationManager;
    private final IJwtTokenService jwtTokenService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AccountServiceImpl(ModelMapper modelMapper, IMailService mailService, IUserService userService,
                              IEmailTokenService emailTokenService,
                              @Qualifier(value = "localeMessageSource") MessageSource messageSource,
                              AuthenticationManager authenticationManager, IJwtTokenService jwtTokenService,
                              PasswordEncoder passwordEncoder) {
        this.modelMapper = modelMapper;
        this.mailService = mailService;
        this.userService = userService;
        this.emailTokenService = emailTokenService;
        this.messageSource = messageSource;
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public ResponseEntity<Object> registration(UserValidationDTO userValidationDTO, BindingResult result,
                                               HttpServletRequest request, Locale locale) {
        VerifyUserResponse verifyUserResponse = userService.verifyUser(userValidationDTO, result, locale);
        if (!verifyUserResponse.isValid()) {
            return new ResponseEntity<>(verifyUserResponse, HttpStatus.BAD_REQUEST);
        }
        User user = modelMapper.map(userValidationDTO, User.class);
        userService.create(user, Role.USER);
        mailService.sendRegistrationConfirmationToken(emailTokenService.buildToken(user),
                user.getEmail(), generateAppBaseUrl(request), locale);
        return new ResponseEntity<>(new MessageResponse(messageSource
                .getMessage("successRegistration", null, locale)), HttpStatus.CREATED);
    }

    private String generateAppBaseUrl(HttpServletRequest request) {
        return String.format("%s://%s:%d", request.getScheme(), request.getServerName(), request.getServerPort());
    }

    @Override
    public ResponseEntity<Object> login(AuthorizationDto authorizationDto, HttpServletRequest request, Locale locale) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(authorizationDto.getEmail(), authorizationDto.getPassword());
        User user = userService.getUserByEmail(authorizationDto.getEmail());
        try {
            Authentication authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(authenticate);
            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
            userService.setLastLoginToUserWithEmail(authorizationDto.getEmail());
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new MessageResponse(messageSource
                    .getMessage("incorrectLoginInfo", null, locale)), HttpStatus.FORBIDDEN);
        } catch (DisabledException e) {
            return new ResponseEntity<>(userService.determineUserStatus(user, locale), HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>(new AuthorizationResponse(UserStatus.ACTIVE), HttpStatus.OK);
    }

    @Override
    public RedirectView confirmRegistration(String token, Locale locale) {
        String email;
        if (emailTokenService.getByToken(token) == null) {
            throw new ConfirmRegistrationJWTInvalidException(messageSource
                    .getMessage("invalidToken", null, locale));
        }
        try {
            email = jwtTokenService.parseEmailTokenAndGetEmail(token);
        } catch (JwtException e) {
            throw new ConfirmRegistrationJWTInvalidException(e.getMessage());
        }
        setStatusActiveAndDeleteToken(token, email);
        return new RedirectView("/loginPage?registrationSuccess");
    }

    private void setStatusActiveAndDeleteToken(String token, String email) {
        User user = userService.getUserByEmail(email);
        user.setUserStatus(UserStatus.ACTIVE);
        userService.update(user);
        emailTokenService.delete(emailTokenService.getByToken(token));
    }

    @Override
    public ResponseEntity<Object> sendMessage(AuthorizationDto authorizationDto, HttpServletRequest request, Locale locale) {
        User user = userService.getUserByEmail(authorizationDto.getEmail());
        if (user == null) {
            return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("disabledUser", null, locale)),
                    HttpStatus.BAD_REQUEST);
        }
        EmailToken emailToken = emailTokenService.getByUserId(user.getId());
        if (emailToken != null) {
            emailTokenService.delete(emailToken);
        }
        EmailToken newEmailToken = new EmailToken();
        newEmailToken.setUser(user);
        newEmailToken.setToken(jwtTokenService.generateAndGetEmailToken(authorizationDto.getEmail()));
        emailTokenService.create(newEmailToken);
        if (user.getUserStatus().equals(UserStatus.REGISTERED_BY_ADMIN)) {
            User userFromDB = userService.getUserByEmail(authorizationDto.getEmail());
            userFromDB.setPassword(userService.generatePassword());
            mailService.sendPasswordAndLogin(newEmailToken, userFromDB.getEmail(), userFromDB.getPassword(),
                    generateAppBaseUrl(request), locale);
            userFromDB.setPassword(userService.encodePassword(userFromDB.getPassword()));
            userService.update(userFromDB);
        } else {
            mailService.sendRegistrationConfirmationToken(newEmailToken, authorizationDto.getEmail(),
                    generateAppBaseUrl(request), locale);
        }
        return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("successEmailSend", null, locale)),
                HttpStatus.OK);
    }

    @Override
    public ResponseEntity<Object> sendForgotPasswordToken(String email, HttpServletRequest request, Locale locale) {
        User user = userService.getActiveUserByEmail(email);
        if (user == null) {
            return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("disabledUser", null, locale)),
                    HttpStatus.BAD_REQUEST);
        }
        EmailToken emailToken = emailTokenService.getByUserId(user.getId());
        if (emailToken != null) {
            emailTokenService.delete(emailToken);
        }
        EmailToken newEmailToken = new EmailToken();
        newEmailToken.setUser(user);
        newEmailToken.setToken(jwtTokenService.generateAndGetEmailToken(email));
        emailTokenService.create(newEmailToken);
        mailService.sendPasswordResetTokenMessageToEmail(newEmailToken, email, generateAppBaseUrl(request), locale);
        return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("successEmailSend", null, locale)),
                HttpStatus.OK);
    }

    @Override
    public RedirectView resetPassword(String token, Locale locale) {
        String email;
        if (emailTokenService.getByToken(token) == null) {
            throw new PasswordResetJWTInvalidException(messageSource.getMessage("invalidToken", null, locale));
        }
        try {
            email = jwtTokenService.parseEmailTokenAndGetEmail(token);
        } catch (JwtException e) {
            throw new PasswordResetJWTInvalidException(e.getMessage());
        }
        User user = userService.getUserByEmail(email);
        Authentication auth = new UsernamePasswordAuthenticationToken(user, null, Arrays.asList(
                new SimpleGrantedAuthority(Role.CHANGE_PASSWORD.toString())));
        SecurityContextHolder.getContext().setAuthentication(auth);
        emailTokenService.delete(emailTokenService.getByToken(token));
        return new RedirectView("/resetPasswordPage");
    }

    @Override
    public ResponseEntity<Object> changePassword(PasswordResetDto passwordResetDto, User user, HttpServletRequest request, Locale locale) {
        String password = passwordResetDto.getPassword();
        String passwordConfirm = passwordResetDto.getConfirmPassword();
        if (password.equals(passwordConfirm)) {
            if (!userService.isPasswordValid(password)) {
                return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("badPassword", null, locale)),
                        HttpStatus.BAD_REQUEST);
            }
            user.setPassword(passwordEncoder.encode(password));
            userService.update(user);
            request.getSession(false).invalidate();
            return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("updatePasswordSuccess", null, locale)),
                    HttpStatus.OK);
        }
        return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("notConfirmed", null, locale)),
                HttpStatus.BAD_REQUEST);
    }

    @Override
    public ResponseEntity<Object> registerUser(RegisterUserDTO userDTO, BindingResult result, HttpServletRequest request,
                                               Locale locale) {
        String password = userService.generatePassword();
        userDTO.setPassword(password);
        VerifyUserResponse verifyUserResponse = userService.verifyUser(userDTO, result, locale);
        if (!verifyUserResponse.isValid()) {
            return new ResponseEntity<>(verifyUserResponse, HttpStatus.BAD_REQUEST);
        }
        User user = modelMapper.map(userDTO, User.class);
        userService.create(user);
        mailService.sendPasswordAndLogin(emailTokenService.buildToken(user), user.getEmail(), password,
                generateAppBaseUrl(request), locale);
        return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("adminAddUser", null, locale)),
                HttpStatus.CREATED);
    }

    @Override
    public RedirectView continueRegistration(String token, Locale locale) {
        if (emailTokenService.getByToken(token) == null) {
            throw new ConfirmRegistrationJWTInvalidException(messageSource.getMessage("invalidToken", null, locale));
        }
        return new RedirectView("/continue-registration?token=" + token);
    }

    @Override
    public ResponseEntity<Object> finishRegistration(String token, ContinueUserRegistrationDTO userDTO,
                                                     BindingResult result, Locale locale) {
        VerifyUserResponse verifyUserResponse = userService.verifyUser(userDTO, result, locale);
        if (!verifyUserResponse.isValid()) {
            return new ResponseEntity<>(verifyUserResponse, HttpStatus.BAD_REQUEST);
        }
        userService.update(userDTO, jwtTokenService.parseEmailTokenAndGetEmail(token));
        emailTokenService.delete(emailTokenService.getByToken(token));
        return new ResponseEntity<>(new MessageResponse(messageSource.getMessage("createdByAdmin", null, locale)),
                HttpStatus.CREATED);
    }
}