package br.com.challenge.repository;

import br.com.challenge.entity.NewUser;
import org.springframework.data.jpa.repository.JpaRepository;


public interface NewUserRepository extends JpaRepository<NewUser, Long> {
}
