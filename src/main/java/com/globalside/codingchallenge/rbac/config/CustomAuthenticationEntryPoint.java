package com.globalside.codingchallenge.rbac.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;


// for the user that is not authenticated or the credentials are invalid:
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String errorMessage = "Authentication is required to access this resource";
    private final ObjectMapper objectMapper;

    public CustomAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        ProblemDetail problem = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        problem.setTitle(HttpStatus.FORBIDDEN.getReasonPhrase());
        problem.setDetail(errorMessage);
        problem.setProperty("path", request.getRequestURI());
        objectMapper.writeValue(response.getOutputStream(), problem);        
    }
}