package br.com.challenge.service.impl;

import br.com.challenge.entity.NewUser;
import br.com.challenge.repository.NewUserRepository;
import br.com.challenge.service.interfaces.NewUserServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class NewUserService implements NewUserServiceInterface {

    @Autowired
    private NewUserRepository newUserRepository;

    @Override
    public void salvarNewUser(NewUser newUser) {
        newUserRepository.save(newUser);
    }

    @Override
    public void deleteNewUserById(Long id) {
        newUserRepository.deleteById(id);
    }

}
