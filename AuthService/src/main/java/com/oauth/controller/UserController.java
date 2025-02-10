package com.oauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.oauth.dto.AuthRequest;
import com.oauth.dto.AuthResponse;
import com.oauth.entity.UserInfo;
import com.oauth.service.JwtService;
import com.oauth.service.UserService;

@RestController
@RequestMapping("/user")
//@CrossOrigin
public class UserController {

	@Autowired
	private UserService service;
	@Autowired
	private JwtService jwtService;

	@Autowired
	private AuthenticationManager authenticationManager;
    
	//@CrossOrigin(origins = "https://0f47-115-98-50-111.ngrok-free.app")
	@GetMapping("/welcome")
	public String welcome() {
		return "Welcome this endpoint is not secure";
	}

	@PostMapping("/newUser")
	public String addNewUser(@RequestBody UserInfo userInfo) {
		return service.addUser(userInfo);
	}

	@GetMapping("/all")
	@PreAuthorize("hasAuthority('ADMIN')")
	public String testAdminRole() {
		return "testing Admin Role";
	}

	@GetMapping("/test/{id}")
	@PreAuthorize("hasAuthority('USER')")
	public String testUserRole(@PathVariable int id) {
		return "testing USER ROLE" + id;
	}

	@PostMapping("/authenticate")
	public ResponseEntity authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        System.out.println("user="+authRequest.getUsername());
        System.out.println("password="+authRequest.getPassword());
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
		if (authentication.isAuthenticated()) {
			System.out.println("test is success");
			String accessToken = jwtService.generateToken(authRequest.getUsername());
			String refreshToken = jwtService.generateRefreshToken(authRequest.getUsername());

			return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
		} else {
			return ResponseEntity.status(401).body("Invalid credentials ");
		}

	}

	@PostMapping("/refresh")
	public ResponseEntity<?> refreshToken(@RequestParam String refreshToken, @RequestParam String userName) {
		if (jwtService.validateToken(refreshToken, userName)) {
			String username = jwtService.extractUserName(refreshToken);
			String newAccessToken = jwtService.generateToken(username);
			return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken));
		}
		return ResponseEntity.status(401).body("Invalid refresh token");
	}
}