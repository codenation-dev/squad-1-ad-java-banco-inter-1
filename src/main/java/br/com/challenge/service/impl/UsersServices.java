package br.com.challenge.service.impl;

import br.com.challenge.dto.UserJobDTO;
import br.com.challenge.entity.Users;
import br.com.challenge.enums.Profile;
import br.com.challenge.exception.AuthorizationException;
import br.com.challenge.exception.ConflictException;
import br.com.challenge.exception.NoContentException;
import br.com.challenge.repository.UsersRepository;
import br.com.challenge.security.UserSS;
import br.com.challenge.service.interfaces.EmailServiceInterface;
import br.com.challenge.service.interfaces.UsersServiceInterface;
import com.sun.jndi.toolkit.url.Uri;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class UsersServices implements UsersServiceInterface {

    @Value("${url.user.activite}")
    private String uri;

    @Autowired
    private UsersRepository usersRepository;

    @Autowired
    private EmailServiceInterface emailService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public List<Users> getUsers() {

        return usersRepository.findAll();
    }

    @Override
    public Users getUser(Long id) {
        UserSS userSS = UserService.authenticated();

        if (userSS == null || !userSS.hasRole(Profile.ADMIN) && !id.equals(userSS.getId())) {
            throw new AuthorizationException("Acesso negado.");
        }

        Optional<Users> users = usersRepository.findById(id);

        if (!users.isPresent()) {
            throw new NoContentException("Usuário não encontrado! Id: " + id + Users.class.getName());
        }
        return users.get();
    }

    @Override
    public Users getUserEmail(String email) {
        return usersRepository.findByEmail(email);
    }

    @Override
    public Users saveUsers(Users users) {

        if (existsUser(users.getEmail())) {
            throw new ConflictException("Usuario já cadastrado com este email. Email: " + users.getEmail());
        }

        users.setPassword(bCryptPasswordEncoder.encode(users.getPassword()));
        users.setToken(Base64.getEncoder().encodeToString(users.getEmail().getBytes()));
        Users user = usersRepository.save(users);
        
        try {
//            user.setUri(uri.concat(user.getToken()));
//            emailService.sendRegisterConfimationEmail(user);
            saveUserJob(user);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return user;
    }

    @Override
    public Users updateUsers(Users users) {

        Users u = usersRepository.getOne(users.getId());
        if (!u.getPassword().equals(users.getPassword())) {
            users.setPassword(bCryptPasswordEncoder.encode(users.getPassword()));
        }

        return usersRepository.save(users);
    }

    @Override
    public void deleteUsers(Long id) {
        usersRepository.deleteById(id);
    }

    @Override
    public String activeUsers(String token) {
        Users users = usersRepository.findUsersByToken(token);

        if (users != null) {
            users.setActive(true);
            updateUsers(users);

            return "Usuário Registrado com sucesso!";
        }
        return "Erro ao ativar o usuário.";
    }

    @Override
    public List<Users> findUsersByActiveFalse() {
        return usersRepository.findUsersByActiveFalse();
    }

    private boolean existsUser(String email) {
        return usersRepository.findByEmail(email) != null;
    }

    private void saveUserJob(Users users){
        String uri = "https://sendemailchallenge.herokuapp.com/users";
        UserJobDTO userJobDTO = new UserJobDTO(users.getName(), users.getEmail(), users.getToken(), false, false);
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.postForObject(uri, userJobDTO, UserJobDTO.class);
    }
}
