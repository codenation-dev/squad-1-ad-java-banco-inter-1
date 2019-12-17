package br.com.challenge.endpoints;

import br.com.challenge.entity.Users;
import br.com.challenge.service.impl.UsersServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("users")
public class UsersResource {

    @Autowired
    private UsersServices usersServices;

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public List<Users> getUsers() {
        return usersServices.getUsers();
    }

    @GetMapping("/{id}")
    @ResponseStatus(HttpStatus.OK)
    public Users getUsers(@PathVariable Long id) {
        return usersServices.getUser(id);
    }

    @GetMapping(params = {"activite"})
    @ResponseStatus(HttpStatus.OK)
    public String activateCustomer(@RequestParam("activite") String token) {
        return usersServices.activeUsers(token);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Users saveUsers(@RequestBody Users users) {
        return usersServices.saveUsers(users);
    }
}