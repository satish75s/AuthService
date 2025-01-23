package com.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
//@EnableDiscoveryClient
public class UserServiceWithOAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceWithOAuthApplication.class, args);
	}

}
