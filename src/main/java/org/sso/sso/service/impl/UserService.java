package org.sso.sso.service.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.sso.sso.repository.UserRepository;
import org.sso.sso.service.IUserService;

@Service
@RequiredArgsConstructor
public class UserService implements IUserService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String iin) throws UsernameNotFoundException {
        return userRepository.getUserByIin(iin).orElseThrow(() -> new UsernameNotFoundException("User not found..."));
    }
}
