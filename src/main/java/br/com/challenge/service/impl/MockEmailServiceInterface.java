package br.com.challenge.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;

public class MockEmailServiceInterface extends AbstractEmailServiceInterface {

    private static final Logger LOG = LoggerFactory.getLogger(MockEmailServiceInterface.class);

    @Override
    public void sendEmail(SimpleMailMessage msg) {
        LOG.info("Simulando envio de email ...");
        LOG.info(msg.toString());
        LOG.info("Email enviado.");
    }

}
