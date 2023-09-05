package com.tpe.security.service;

import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {


    private String jwtSecret ="sboot";

    private long jwtExpirationMs = 86400000; // 60*60*24*1000 ( 1 GUN )

    // !!! **********  GENERATE TOKEN ****************************
    public String generateToken(Authentication authentication){

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date()).
                setExpiration(new Date(new Date().getTime() + jwtExpirationMs)).
                signWith(SignatureAlgorithm.HS512, jwtSecret).
                compact();
    }


    // !!!  **********  VALIDATE TOKEN ****************************
    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }


    // !!!  **********  Get UserName from TOKEN *******************
    public String getUserNameFromJwtToken(String token){

        return Jwts.parser().
                setSigningKey(jwtSecret).
                parseClaimsJws(token).
                getBody().
                getSubject();
    }
}