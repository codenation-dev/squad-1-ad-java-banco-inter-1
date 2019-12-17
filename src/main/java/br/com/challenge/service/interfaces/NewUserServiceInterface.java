package br.com.challenge.service.interfaces;

import br.com.challenge.entity.NewUser;

public interface NewUserServiceInterface {

    void salvarNewUser(NewUser newUser);

    void deleteNewUserById(Long id);
}
