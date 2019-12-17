package br.com.challenge.configuration;


import br.com.challenge.service.impl.DBService;
import br.com.challenge.service.impl.MockEmailServiceInterface;
import br.com.challenge.service.interfaces.EmailServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("test")
public class TestConfig {

    @Autowired
    private DBService dbService;

    @Bean
    public boolean instantiateDatabase() {
        dbService.instantiateTestDatabase();
        return true;
    }

    @Bean
    public EmailServiceInterface emailService() {
        return new MockEmailServiceInterface();
    }
}