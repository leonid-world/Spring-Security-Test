package io.security.springsecuritypractice.service;

import io.security.springsecuritypractice.repository.UserRepository;
import io.security.springsecuritypractice.domain.entity.Account;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Transactional
    public void createUser(Account account){
        userRepository.save(account);
    }
}
