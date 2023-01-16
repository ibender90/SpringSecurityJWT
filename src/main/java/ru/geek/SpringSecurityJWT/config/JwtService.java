package ru.geek.SpringSecurityJWT.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY="597133743677397A244326462948404D635166546A576E5A7234753778214125"; //https://www.allkeysgenerator.com/ encryption key 256 bit HEX

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails); //Token with empty hash map
    }

    public boolean isTokenValid(String jsonWebToken, UserDetails userDetails){
        final String username = extractUserEmail(jsonWebToken);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(jsonWebToken);
    }

    private boolean isTokenExpired(String jsonWebToken) {
        return extractExpiration(jsonWebToken).before(new Date());
    }

    private Date extractExpiration(String jsonWebToken) {
        return extractSingleClaim(jsonWebToken, Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24 )) //24 hours valid token
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) //for 256 bit key
                .compact();
    }
    public String extractUserEmail(String jsonWebToken) {
        return extractSingleClaim(jsonWebToken, Claims::getSubject);
    }

    public <T> T extractSingleClaim(
            String jsonWebToken,
            Function<Claims, T> claimsResolver){

        final Claims claims = extractAllClaims(jsonWebToken);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jsonWebToken){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jsonWebToken)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
