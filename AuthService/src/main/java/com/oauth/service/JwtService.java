package com.oauth.service;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private String secretkey = "FFfrrXM7zzb6BKjBIGCV0wOLbUYya50la6iJBYvB21o=";
	@Value("${app.jwt.expiration.access}")
	private Long accessTokenExpiration;

	@Value("${app.jwt.expiration.refresh}")
	private Long refreshTokenExpiration;

	/*
	 * public JwtService() {
	 * 
	 * try { KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256"); SecretKey
	 * sk = keyGen.generateKey(); secretkey =
	 * Base64.getEncoder().encodeToString(sk.getEncoded());
	 * System.out.println("secretkey="+secretkey); } catch (NoSuchAlgorithmException
	 * e) { throw new RuntimeException(e); } }
	 */

	public String generateToken(String username) {
		Map<String, Object> claims = new HashMap<>();
		return Jwts.builder().claims().add(claims).subject(username).issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + accessTokenExpiration)).and().signWith(getKey())
				.compact();

	}

	// Generate JWT token for refresh
	public String generateRefreshToken(String username) {
		Map<String, Object> claims = new HashMap<>();
		return Jwts.builder().claims().add(claims).subject(username).issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + refreshTokenExpiration)).and().signWith(getKey())
				.compact();
	}

	private SecretKey getKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secretkey);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	public String extractUserName(String token) {
		// extract the username from jwt token
		return extractClaim(token, Claims::getSubject);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parser().verifyWith(getKey()).build().parseSignedClaims(token).getPayload();
	}

	public boolean validateToken(String token, String username) {
		final String userName = extractUserName(token);
		return (userName.equals(username) && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

}