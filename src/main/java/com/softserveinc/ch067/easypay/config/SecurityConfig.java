package com.softserveinc.ch067.easypay.config;


import com.softserveinc.ch067.easypay.model.Role;
import com.softserveinc.ch067.easypay.service.impl.UserPrincipalDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserPrincipalDetailServiceImpl userPrincipalDetailService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/admin/**").hasAuthority(Role.ADMIN.toString())
                .antMatchers("/user/**").hasAuthority(Role.USER.toString())
                .antMatchers("/manager/**").hasAuthority(Role.MANAGER.toString())
                .antMatchers("/inspector/**").hasAuthority(Role.INSPECTOR.toString())
                .antMatchers("/profile/**", "/home/**", "/ratings/**").authenticated()
                .antMatchers("/resetPasswordPage/**").hasAuthority(Role.CHANGE_PASSWORD.toString())
                .antMatchers("/finish-social-registration/**").hasAuthority(Role.FINISH_SOCIAL_REGISTRATION.toString())
                .anyRequest().permitAll()
                .and()
                .formLogin().loginPage("/loginPage")
                .and()
                .oauth2Login().loginPage("/loginPage")
                .defaultSuccessUrl("/social/success", true).failureUrl("/loginPage?socialError")
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/loginPage?logout").deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .and()
                .exceptionHandling().accessDeniedPage("/resources/html/errors/403.html");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userPrincipalDetailService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
