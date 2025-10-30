package com.example.thehungryhubbackend;

import com.example.thehungryhubbackend.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class TheHungryHubBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(TheHungryHubBackendApplication.class, args);
    }

}
