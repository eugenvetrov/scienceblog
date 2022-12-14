package com.sci.scienceblog;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@Configuration
@EnableJpaRepositories
@EnableTransactionManagement
@EnableAutoConfiguration
public class ScienceblogApplication {

	public static void main(String[] args) {
		SpringApplication.run(ScienceblogApplication.class, args);
	}

}
