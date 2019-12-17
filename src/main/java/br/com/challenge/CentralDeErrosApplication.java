package br.com.challenge;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
//@EnableScheduling
public class CentralDeErrosApplication {

    public static void main(String[] args) {
        SpringApplication.run(CentralDeErrosApplication.class, args);
    }

}
