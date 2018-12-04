package com.softserveinc.ch067.easypay.config;

import com.softserveinc.ch067.easypay.controller.interceptor.InspectorBelongsToUtilityInterceptor;
import com.softserveinc.ch067.easypay.controller.interceptor.ScheduleItemExistInterceptor;
import com.softserveinc.ch067.easypay.controller.interceptor.ScheduleItemRefreshDateInterceptor;
import com.softserveinc.ch067.easypay.controller.interceptor.UserIsAlreadyLoggedInInterceptor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.ResourceHttpMessageConverter;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.spring5.SpringTemplateEngine;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;


@Configuration
@EnableWebMvc
@EnableAspectJAutoProxy
@ComponentScan("com.softserveinc.ch067.easypay")
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    @Qualifier(value = "checksDir")
    private String checksDir;

    @Autowired
    @Qualifier("validationMessageSource")
    private ReloadableResourceBundleMessageSource messageSource;

    @Autowired
    @Qualifier(value = "resourceHandlerFilesDir")
    private String resourceHandlerFilesDir;

    @Autowired
    private ScheduleItemRefreshDateInterceptor scheduleItemRefreshDateInterceptor;

    @Autowired
    private ScheduleItemExistInterceptor scheduleItemExistInterceptor;

    @Autowired
    private InspectorBelongsToUtilityInterceptor inspectorBelongsToUtilityInterceptor;

    @Autowired
    private UserIsAlreadyLoggedInInterceptor userIsAlreadyLoggedInInterceptor;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/resources/**").addResourceLocations("/resources/");
        registry.addResourceHandler("swagger-ui.html").addResourceLocations("classpath:/META-INF/resources/");
        registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");
        registry.addResourceHandler(resourceHandlerFilesDir + "checks/**")
                .addResourceLocations("file:///" + checksDir)
                .setCachePeriod(3600);
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        //registry.addViewController("/").setViewName("/resources/html/index.html");
        registry.addViewController("/").setViewName("/resources/html/cover.html");
        registry.addViewController("/home").setViewName("/resources/html/index.html");
        registry.addViewController("/loginPage").setViewName("/resources/html/login.html");
        registry.addViewController("/user/paymentsHistoryPage").setViewName("/resources/html/payments-history.html");
        registry.addViewController("/user/paymentsPage").setViewName("/resources/html/payments.html");
        registry.addViewController("/user/addresses").setViewName("/resources/html/user_cabinet.html");
        registry.addViewController("/user/rate/").setViewName("/resources/html/user-rate-inspectors.html");
        registry.addViewController("/inspector/schedule/").setViewName("/resources/html/schedule-inspector.html");
        registry.addViewController("/inspector/rate/").setViewName("/resources/html/inspector-rate-users.html");
        registry.addViewController("/inspector/addresses/counters/").setViewName("/resources/html/inspector-counters.html");
        registry.addViewController("/manager/schedule/").setViewName("/resources/html/schedule-manager.html");
        registry.addViewController("/manager/schedule/inspector/**/").setViewName("/resources/html/manager-inspector-schedule-history.html");
        registry.addViewController("/forgotPasswordPage").setViewName("/resources/html/forgot-password.html");
        registry.addViewController("/resetPasswordPage").setViewName("/resources/html/reset-password.html");
        registry.addViewController("/admin/utilitiesPage").setViewName("/resources/html/utilitiesManagement.html");
        registry.addViewController("/admin/management-users").setViewName("/resources/html/user_list.html");
        registry.addViewController("/admin/management-addresses").setViewName("/resources/html/management-addresses.html");
        registry.addViewController("/profile").setViewName("/resources/html/user-profile.html");
        registry.addViewController("/registration").setViewName("/resources/html/registrationPage.html");
        registry.addViewController("/manager/utility/price").setViewName("/resources/html/manager-utility.html");
        registry.addViewController("/user/connected-utilities/").setViewName("/resources/html/connected_utilities.html");
        registry.addViewController("/user/utilities").setViewName("/resources/html/utilities.html");
        registry.addViewController("/registrationPage").setViewName("/resources/html/registrationPage.html");
        registry.addViewController("/robots.txt").setViewName("/resources/robots.txt");
        registry.addViewController("/admin/register-user").setViewName("/resources/html/registration-user.html");
        registry.addViewController("/continue-registration").setViewName("/resources/html/continueRegistration.html");
        registry.addViewController("/finish-social-registration").setViewName("/resources/html/finishSocialRegistration.html");
        registry.addViewController("/favicon.ico").setViewName("/resources/images/logo.png");
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
        interceptor.setParamName("lang");
        registry.addInterceptor(interceptor);
        registry.addInterceptor(scheduleItemExistInterceptor)
                .addPathPatterns("/scheduleHistory/schedule/item/{id}", "/manager/schedule/item/{id}");
        registry.addInterceptor(scheduleItemRefreshDateInterceptor)
                .addPathPatterns("/scheduleHistory/schedule/item/{id}");

        registry.addInterceptor(inspectorBelongsToUtilityInterceptor)
                .addPathPatterns("/manager/schedule/inspector/{id}",
                        "/manager/schedule/item/{id}",
                        "/manager/schedule/item/inspector/{id}",
                        "/manager/schedule/item/list/inspector/{id}",
                        "/manager/schedule/inspector/{id}/",
                        "/manager/schedule/inspector/{id}/history/previous",
                        "/manager/schedule/inspector/{id}/history/current",
                        "/manager/schedule/inspector/{id}/history/previous/**",
                        "/manager/schedule/inspector/{id}/history/current/**"
                );

        registry.addInterceptor(userIsAlreadyLoggedInInterceptor)
                .addPathPatterns("/", "/loginPage", "/registrationPage");
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Bean
    public MultipartResolver multipartResolver() {
        CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver();
        multipartResolver.setMaxUploadSizePerFile(10485760);
        return multipartResolver;
    }

    @Bean
    public JavaMailSender getJavaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);

        mailSender.setUsername("ch067.easypay@gmail.com");
        mailSender.setPassword("PaSsW0rd");

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "true");

        return mailSender;
    }

    @Bean
    public ResourceBundleMessageSource emailMessageSource() {
        final ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("mail/MailMessages");
        messageSource.setDefaultEncoding("UTF-8");
        return messageSource;
    }

    private ITemplateResolver htmlTemplateResolver() {
        final ClassLoaderTemplateResolver templateResolver = new ClassLoaderTemplateResolver();
        templateResolver.setOrder(1);
        templateResolver.setPrefix("/timeleaf-templates/");
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setCharacterEncoding("UTF-8");
        templateResolver.setCacheable(true);
        return templateResolver;
    }

    @Bean
    public TemplateEngine emailTemplateEngine() {
        final SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(htmlTemplateResolver());
        templateEngine.setTemplateEngineMessageSource(emailMessageSource());
        return templateEngine;
    }

    @Override
    public Validator getValidator() {
        LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
        validator.setValidationMessageSource(messageSource);
        return validator;
    }

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new ResourceHttpMessageConverter());
    }
}
