package com.sprint.security.jwt.example.jwtsecurity;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sprint.security.jwt.example.service.UserDetailsServiceImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    /**
     * parsing & validating JWT
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

                // get username from json web token
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // get user data from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                // token contains username and password and authorisations
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // builds authentication and adds to token
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // set current user details into securitycontextholder
                // securitycontextholder where we store details if the present security context of the app
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch(Exception e) {
            logger.error("User authentication issue: {}", e);
        }

        // make the filter available by callin next filter in the chain
        filterChain.doFilter(request, response); 
    }

    /**
     * get authorization header
     */
    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }

    
}