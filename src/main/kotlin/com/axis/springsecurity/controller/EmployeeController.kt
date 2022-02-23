package com.axis.springsecurity.controller

import com.axis.springsecurity.model.JwtRequest
import com.axis.springsecurity.model.JwtResponse
import com.axis.springsecurity.service.UserService
import com.axis.springsecurity.utility.JwtUtility
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class EmployeeController(
    @Autowired val authenticationManager: AuthenticationManager,
    @Autowired val userService: UserService,
    @Autowired val jwtUtility: JwtUtility
) {

    @GetMapping("/helloworld")
    fun helloWorld(): String {
        return "Hello World"
    }

    @PostMapping("/authenticate")
    fun authenticate(@RequestBody jwtRequest: JwtRequest): JwtResponse {
        try {
            authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(
                    jwtRequest.username,
                    jwtRequest.password
                )
            )
        } catch (ex: BadCredentialsException) {
            throw ex
        }

        val userDetails = userService.loadUserByUsername(jwtRequest.username)
        val token = jwtUtility.generateToken(userDetails)
        return JwtResponse(token)
    }

}