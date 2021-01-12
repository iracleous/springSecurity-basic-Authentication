package gr.codehub.service;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> roles=null;
        if(username.equals("admin"))
        {
            roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"));
            return new User("admin", bCryptPasswordEncoder.encode("admin"),
                    roles);
        }
        else if(username.equals("user"))
        {
            roles = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
            return new User("user", bCryptPasswordEncoder.encode("user"),
                    roles);
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }

}