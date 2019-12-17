package br.com.challenge.service.interfaces;

import br.com.challenge.entity.Users;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

@Service
public interface EmailServiceInterface {


    void sendRegisterConfimationEmail(Users user);

    void sendEmail(SimpleMailMessage msg);

    void sendNewPasswordEmail(Users user, String newPass);
}
