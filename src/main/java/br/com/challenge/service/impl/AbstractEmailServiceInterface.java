package br.com.challenge.service.impl;

import br.com.challenge.entity.Users;
import br.com.challenge.service.interfaces.EmailServiceInterface;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;

import java.util.Date;


public abstract class AbstractEmailServiceInterface implements EmailServiceInterface {

    @Value("${default.sender}")
    private String sender;


    @Override
    public void sendRegisterConfimationEmail(Users user) {
        SimpleMailMessage sm = prepareSimpleMailMessageFromCustomer(user);
        sendEmail(sm);
    }

    protected SimpleMailMessage prepareSimpleMailMessageFromCustomer(Users user) {
        SimpleMailMessage sm = new SimpleMailMessage();
        sm.setTo(user.getEmail());
        sm.setFrom(sender);
        sm.setSubject("User successfully registered!: " + user.getId());
        sm.setSentDate(new Date(System.currentTimeMillis()));
        sm.setText(user.toString());
        return sm;
    }

    @Override
    public void sendNewPasswordEmail(Users user, String newPass) {
        SimpleMailMessage sm = prepareNewPasswordEmail(user, newPass);
        sendEmail(sm);
    }

    protected SimpleMailMessage prepareNewPasswordEmail(Users user, String newPass) {
        SimpleMailMessage sm = new SimpleMailMessage();
        sm.setTo(user.getEmail());
        sm.setFrom(sender);
        sm.setSubject("New Password Request");
        sm.setSentDate(new Date(System.currentTimeMillis()));
        sm.setText("New password: " + newPass);
        return sm;
    }
}

