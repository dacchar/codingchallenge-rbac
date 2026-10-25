package com.globalside.codingchallenge.rbac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.http.HttpServletResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.globalside.codingchallenge.rbac.constants.SecuriryConstants;

@Configuration
@EnableMethodSecurity               // enable method security
public class SecurityConfig {

    private static final String errorMessage = "You do not have permission to access this resource.";

    // Maping users, credentails and roles
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
                .withUsername(SecuriryConstants.USER_NAME)
                .password(passwordEncoder().encode(SecuriryConstants.USER_PASSWORD))
                .roles(SecuriryConstants.USER_ROLE)
                .build();

        UserDetails admin = User
                .withUsername(SecuriryConstants.ADMIN_NAME)
                .password(passwordEncoder().encode(SecuriryConstants.ADMIN_PASSWORD))
                .roles(SecuriryConstants.ADMIN_ROLE)
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    // Securely hashes passwords using the BCrypt algorithm.
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, CustomAuthenticationEntryPoint entryPoint, ObjectMapper objectMapper) throws Exception {
        httpSecurity.csrf(csrfCustomizer -> csrfCustomizer.disable());                              // Disable CSRF protection
        httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());        // All requests should be authenticated
        httpSecurity.httpBasic(basic -> basic.authenticationEntryPoint(entryPoint));                // Enable HTTP Basic authentication
        
        httpSecurity
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))   // no HTTP session to store the user's security context.
            .exceptionHandling(exception -> exception

                // for the user that is not authenticated or the credentials are invalid:
                .authenticationEntryPoint(entryPoint)
                
                // for authenticated users who lack permission:
                .accessDeniedHandler((request, response, ex) -> {
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.setContentType("application/json");

                        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
                        problem.setTitle(HttpStatus.FORBIDDEN.getReasonPhrase());
                        problem.setDetail(errorMessage);
                        problem.setProperty("path", request.getRequestURI());
                        objectMapper.writeValue(response.getOutputStream(), problem);                        
                    })                
            );

        return httpSecurity.build();
    }
}
