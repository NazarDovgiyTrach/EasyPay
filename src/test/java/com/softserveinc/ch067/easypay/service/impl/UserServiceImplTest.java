package com.softserveinc.ch067.easypay.service.impl;


import com.softserveinc.ch067.easypay.config.DatabaseConfigTest;
import com.softserveinc.ch067.easypay.dao.IUserDAO;
import com.softserveinc.ch067.easypay.dto.NewPasswordDTO;
import com.softserveinc.ch067.easypay.dto.UserDataDTO;
import com.softserveinc.ch067.easypay.exception.InvalidDataException;
import com.softserveinc.ch067.easypay.model.User;
import com.softserveinc.ch067.easypay.service.IGoogleDriveService;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;

import java.io.IOException;


@RunWith(MockitoJUnitRunner.class)
@ContextConfiguration(classes = {DatabaseConfigTest.class})
public class UserServiceImplTest {


    static private User USER_EXAMPLE = new User();
    static String USER_PASSWORD = "Admin123";
    static String ENCODED_USER_PASSWORD = "$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS";

    private static UserDataDTO USERDATADTO_EXAMPLE = new UserDataDTO();
    private static UserDataDTO USERDATADTO_WITHOUT_CHANGES = new UserDataDTO();
    private static NewPasswordDTO NEWPASSWORDDTO_EXAMPLE = new NewPasswordDTO();
    private static NewPasswordDTO NEWPASSWORDDTO_WITH_INCORRECT_CURRENT_PASSWORD_EXAMPLE = new NewPasswordDTO();
    private static byte[] IMAGE_BYTES;

    private static String GENERATED_GOOGLE_DRIVE_FILE_ID = "fileId";


    @Mock
    private IUserDAO userDAO;

    @Mock
    private IGoogleDriveService googleDriveService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    @BeforeClass
    public static void before() {
        USER_EXAMPLE.setName("User");
        USER_EXAMPLE.setSurname("Userenko");
        USER_EXAMPLE.setEmail("user@gmail.com");
        USER_EXAMPLE.setPhoneNumber("+380997894512");
        USER_EXAMPLE.setPassword(ENCODED_USER_PASSWORD);

        USERDATADTO_EXAMPLE.setName("Ivan");
        USERDATADTO_EXAMPLE.setSurname("Malkin");
        USERDATADTO_EXAMPLE.setPhoneNumber("+380993831412");

        USERDATADTO_WITHOUT_CHANGES.setName(USER_EXAMPLE.getName());
        USERDATADTO_WITHOUT_CHANGES.setSurname(USER_EXAMPLE.getSurname());
        USERDATADTO_WITHOUT_CHANGES.setPhoneNumber(USER_EXAMPLE.getPhoneNumber());

        NEWPASSWORDDTO_EXAMPLE.setOldPassword(USER_PASSWORD);
        NEWPASSWORDDTO_EXAMPLE.setNewPassword("He110ooo");

        NEWPASSWORDDTO_WITH_INCORRECT_CURRENT_PASSWORD_EXAMPLE.setOldPassword(USER_PASSWORD + "123");
        NEWPASSWORDDTO_WITH_INCORRECT_CURRENT_PASSWORD_EXAMPLE.setNewPassword("123Pllaaa");

        IMAGE_BYTES = new byte[5];


    }

    @Before
    public void setMocks() {
        Mockito.when(userDAO.getUserByEmail(USER_EXAMPLE.getEmail())).thenReturn(USER_EXAMPLE);
        Mockito.when(passwordEncoder.
                matches(USER_PASSWORD, ENCODED_USER_PASSWORD)).thenReturn(Boolean.TRUE);
        Mockito.when(googleDriveService.createPNGFile(Mockito.any(), Mockito.any(), Mockito.any())).
                thenReturn(GENERATED_GOOGLE_DRIVE_FILE_ID);
    }


    @Test
    public void updateUserInfo_updateNameSurnameAndEmail_successful() throws IOException, InvalidDataException {
        userService.updateUserInfo(USER_EXAMPLE.getEmail(), USERDATADTO_EXAMPLE, null, null);
        Mockito.verify(userDAO, Mockito.times(1)).update(Mockito.any());
        Mockito.verify(passwordEncoder, Mockito.times(0)).matches(Mockito.any(), Mockito.any());
        Mockito.verify(googleDriveService, Mockito.times(0)).createPNGFile(Mockito.any(),
                Mockito.any(), Mockito.any());

    }

    @Test
    public void updateUserInfo_updatePassword_successful() throws IOException, InvalidDataException {
        userService.updateUserInfo(USER_EXAMPLE.getEmail(), USERDATADTO_WITHOUT_CHANGES, NEWPASSWORDDTO_EXAMPLE, null);
        Mockito.verify(userDAO, Mockito.times(1)).update(Mockito.any());
        Mockito.verify(passwordEncoder, Mockito.times(1)).matches(Mockito.any(), Mockito.any());
        Mockito.verify(passwordEncoder, Mockito.times(1)).encode(NEWPASSWORDDTO_EXAMPLE.getNewPassword());
        Mockito.verify(googleDriveService, Mockito.times(0)).createPNGFile(Mockito.any(),
                Mockito.any(), Mockito.any());

    }

    @Test(expected = InvalidDataException.class)
    public void updateUserInfo_updatePassword_failReasonIsCurrentPasswordInvalid() throws IOException, InvalidDataException {
        userService.updateUserInfo(USER_EXAMPLE.getEmail(), USERDATADTO_WITHOUT_CHANGES, NEWPASSWORDDTO_WITH_INCORRECT_CURRENT_PASSWORD_EXAMPLE, null);
        Mockito.verify(userDAO, Mockito.times(1)).update(Mockito.any());
        Mockito.verify(passwordEncoder, Mockito.times(1)).matches(Mockito.any(), Mockito.any());
        Mockito.verify(passwordEncoder, Mockito.times(0)).encode(Mockito.any());
        Mockito.verify(googleDriveService, Mockito.times(0)).createPNGFile(Mockito.any(),
                Mockito.any(), Mockito.any());

    }

    @Test
    public void updateUserInfo_updateAvatar_successful() throws IOException, InvalidDataException {
        userService.updateUserInfo(USER_EXAMPLE.getEmail(), USERDATADTO_WITHOUT_CHANGES, null, IMAGE_BYTES);
        Mockito.verify(userDAO, Mockito.times(1)).update(Mockito.any());
        Mockito.verify(passwordEncoder, Mockito.times(0)).matches(Mockito.any(), Mockito.any());
        Mockito.verify(googleDriveService, Mockito.times(1)).createPNGFile(Mockito.any(),
                Mockito.any(), Mockito.any());
    }


}
