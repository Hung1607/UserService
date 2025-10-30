package com.example.thehungryhubbackend.security;

import com.example.thehungryhubbackend.config.AppProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

//    public String createToken(Authentication authentication) {
//        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
//
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());
//
//        return Jwts.builder()
//                .setSubject(userPrincipal.getId())
//                .setIssuedAt(new Date())
//                .setExpiration(expiryDate)
//                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
//                .compact();
//    }

    public String getUsernameFromToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(appProperties.getAuth().getTokenSecret().getBytes());

        JwtParser parser = Jwts.parser()
                .setSigningKey(key)
                .build();

        Claims claims = parser.parseClaimsJws(token).getBody();

        // You can change this depending on the exact claim name
        return claims.get("username", String.class);
    }

    public boolean validateToken(String authToken) {
        try {
            System.out.print("check \n");
            SecretKey key = Keys.hmacShaKeyFor(appProperties.getAuth().getTokenSecret().getBytes());

            Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(authToken);

            return true;
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }

}