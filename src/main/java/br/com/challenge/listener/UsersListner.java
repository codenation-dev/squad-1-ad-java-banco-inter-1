package br.com.challenge.listener;

import br.com.challenge.entity.Users;
import br.com.challenge.service.impl.NewUserService;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.PostLoad;

public class UsersListner {

    @Autowired
    private NewUserService newUserService;

    @PostLoad
    public void deleteNewUserActivite(Users user) {
        if (user.isActive()) {
            newUserService.deleteNewUserById(user.getId());
        }
    }
}
