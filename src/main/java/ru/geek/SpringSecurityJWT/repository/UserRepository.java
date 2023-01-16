package ru.geek.SpringSecurityJWT.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.geek.SpringSecurityJWT.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
}
