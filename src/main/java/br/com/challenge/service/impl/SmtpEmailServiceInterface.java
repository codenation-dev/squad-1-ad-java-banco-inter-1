package br.com.challenge.service.impl;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

public class SmtpEmailServiceInterface extends AbstractEmailServiceInterface {


    private static final Logger LOG = LoggerFactory.getLogger(SmtpEmailServiceInterface.class);
    @Autowired
    private MailSender mailSender;

    @Override
    public void sendEmail(SimpleMailMessage msg) {
        LOG.info("Sending email ...");
        mailSender.send(msg);
        LOG.info("Email sent");
    }
}