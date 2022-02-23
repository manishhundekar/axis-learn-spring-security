package com.axis.springsecurity.utility

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component
import java.io.Serializable
import java.util.*

@Component
class JwtUtility : Serializable {

    @Value("\${jwt.secret}")
    val secretKey: String? = null

    val tokenValiditySeconds = (5 * 60 * 60).toLong()

    fun generateToken(userDetails: UserDetails): String {
        return Jwts
            .builder()
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + tokenValiditySeconds * 1000))
            .signWith(SignatureAlgorithm.HS512, secretKey)
            .compact()
    }

    fun validateToken(token: String, userDetails: UserDetails): Boolean {
        val claims = getClaims(token)
        val subject = claims.subject
        val expiration = claims.expiration
        return subject == userDetails.username && !expiration.before(Date())
    }

    fun getClaims(token: String): Claims {
        return Jwts
            .parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .body
    }
}