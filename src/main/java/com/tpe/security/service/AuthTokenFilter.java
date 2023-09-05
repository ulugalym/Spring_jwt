package com.tpe.security.service;

import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//@RequiredArgsConstructor
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private  JwtUtils jwtUtils;

    @Autowired
    private  UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // !!! request icinden tokeni aliyoruz
        String jwtToken = parseJwt(request);

        try {
            if(jwtToken!=null && jwtUtils.validateToken(jwtToken)) {

                String userName = jwtUtils.getUserNameFromJwtToken(jwtToken);

                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
                // buradan itibaren Authenticate edilen kullaniciyi contexte atmak
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
                        null,userDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }
        //!!! request ve response icin filter olarak ekliyorum
        filterChain.doFilter(request, response);

    }

    private String parseJwt(HttpServletRequest request){

        String header = request.getHeader("Authorization");
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")){
            return header.substring(7);
        }

        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        AntPathMatcher antMatcher = new AntPathMatcher();

        return antMatcher.match("/register", request.getServletPath()) ||
                antMatcher.match("/login", request.getServletPath());
    }
}