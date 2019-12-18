package br.com.challenge.security;


import br.com.challenge.dto.CredentialsDTO;
import br.com.challenge.exception.UsersDisabledException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    private JWTUtil jwtUtil;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {

        setAuthenticationFailureHandler(new JWTAuthenticationFailureHandler());
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {

        try {

            CredentialsDTO credentials = new ObjectMapper().readValue(req.getInputStream(), CredentialsDTO.class);

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(credentials.getEmail(), credentials.getPassword(), new ArrayList<>());

            Authentication auth = authenticationManager.authenticate(authToken);
            return auth;
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth)
            throws IOException, ServletException {

        String username = ((UserSS) auth.getPrincipal()).getUsername();
        String token = jwtUtil.generateToken(username);
        response.addHeader("Authorization", "Bearer " + token);
    }

    private class JWTAuthenticationFailureHandler implements AuthenticationFailureHandler {

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
                throws IOException, ServletException {

            response.setContentType("application/json");
            if (exception != null && exception.getCause() != null && exception.getCause().toString().equals(UsersDisabledException.class.getName())) {

                response.setStatus(403);
                response.getWriter().append(getJsonResponse("403", "Não autorizado", "Confirmação de e-mail pendente"));
            }
            else {

                response.setStatus(401);
                response.getWriter().append(getJsonResponse("401", "Não autorizado", "Email ou senha inválidos"));
            }
        }

        private String getJsonResponse(String statusCode, String error, String message) {

            Long date = new Date().getTime();

            return "{"
                    .concat("\"timestamp\": ").concat(date.toString()).concat(", ")
                    .concat("\"status\": ").concat(statusCode).concat(", ")
                    .concat("\"error\": \"").concat(error).concat("\", ")
                    .concat("\"message\": \"").concat(message).concat("\", ")
                    .concat("\"path\": \"/login\"")
                    .concat("}");
        }
    }
}