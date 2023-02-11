package com.pts.Service;

import com.pts.DAO.AccountDAO;
import com.pts.entity.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    AccountDAO accountDAO;
    @Autowired
    BCryptPasswordEncoder pe;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            Account account = accountDAO.laytk(username);
            if(!account.getTps_Active()){
                throw new UsernameNotFoundException(username + " is not active!");

            }
            //tao userDetails tu Account
            username=account.getTps_Username();
            Boolean trangThai=account.getTps_Active();
            String password = account.getTps_Password();
            String[] roles = account.getAuthorities().stream()
                    .map(au -> au.getRole().getTps_Id())
                    .collect(Collectors.toList()).toArray(new String[0]);

            return User.withUsername(username)
                    .password(pe.encode(password))
                    .roles(roles).build();
        } catch (Exception e) {
            throw new UsernameNotFoundException(username + "not found!");
        }
    }
}
