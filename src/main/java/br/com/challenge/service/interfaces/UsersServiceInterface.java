package br.com.challenge.service.interfaces;

import br.com.challenge.entity.Users;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UsersServiceInterface {

    List<Users> getUsers();

    Users getUser(Long id);

    Users getUserEmail(String email);

    Users saveUsers(Users users);

    Users updateUsers(Users users);

    void deleteUsers(Long id);

    String activeUsers(String token);

    List<Users> findUsersByActiveFalse();
}
