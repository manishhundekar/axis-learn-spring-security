package com.axis.springsecurity.service

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserService : UserDetailsService {
    override fun loadUserByUsername(username: String): UserDetails {
        //userRepository.findByUsername(username)
        if (username == "admin") {
            return User("admin", "123456", listOf())
        }
        throw UsernameNotFoundException("Invalid username")
    }
}