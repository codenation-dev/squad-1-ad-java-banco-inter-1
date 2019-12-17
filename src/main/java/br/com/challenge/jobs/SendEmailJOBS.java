package br.com.challenge.jobs;

import br.com.challenge.entity.NewUser;
import br.com.challenge.entity.Users;
import br.com.challenge.service.impl.NewUserService;
import br.com.challenge.service.impl.UsersServices;
import br.com.challenge.service.interfaces.EmailServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.List;

@Component
public class SendEmailJOBS {

    @Autowired
    private UsersServices usersServices;

    @Autowired
    private EmailServiceInterface emailService;

    @Autowired
    private NewUserService newUserService;


    @Scheduled(fixedRate = 30000)
    @Transactional
    public void enviaEmailUsuarioActiveFalse() {
        List<Users> usersList = usersServices.findUsersByActiveFalse();

        for (Users user : usersList) {
            emailService.sendRegisterConfimationEmail(user);
            newUserService.salvarNewUser(NewUser.builder().users(user).build());
        }
    }
}
