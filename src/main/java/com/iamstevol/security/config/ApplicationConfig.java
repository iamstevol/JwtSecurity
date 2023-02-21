package com.iamstevol.security.config;

import com.iamstevol.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;
    /*
    Initially return new UserDetailsService was pressed which will over the loadUserByUsername method.
    But lambda was used to reduce the code length, then we use the userRepository to find the user by email.
    Finally, it was turned into method reference.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return userRepository::findByEmail;
    }

    /*
    Auth provider is the data access object, which fetches user detail including username and password
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        //Fetching the user details by using the userDetailsService specified above
        authProvider.setUserDetailsService(userDetailsService());
        /*It also specifies the type of password encoder used, so that when we want to authenticate a user
        we can know the right passwordEncoder in order to decode the password using the right algorithm
         */
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
