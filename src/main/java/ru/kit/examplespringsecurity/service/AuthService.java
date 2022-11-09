package ru.kit.examplespringsecurity.service;

import io.jsonwebtoken.Claims;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import ru.kit.examplespringsecurity.exception.AuthException;
import ru.kit.examplespringsecurity.model.JwtAuthentication;
import ru.kit.examplespringsecurity.model.JwtRequest;
import ru.kit.examplespringsecurity.model.JwtResponse;
import ru.kit.examplespringsecurity.model.User;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {
  private final UserService userService;
  private final Map<String, String> refreshStorage = new HashMap<>();
  private final JwtProvider jwtProvider;

  public JwtResponse login(@NonNull JwtRequest authRequest) {
    final User user =
        userService
            .getByLogin(authRequest.getLogin())
            .orElseThrow(() -> new AuthException("User now found"));
    if (user.getPassword().equals(authRequest.getPassword())) {
      final String accessToken = jwtProvider.generateAccessToken(user);
      final String refreshToken = jwtProvider.generateRefreshToken(user);
      refreshStorage.put(user.getLogin(), refreshToken);
      return new JwtResponse(accessToken, refreshToken);
    } else {
      throw new AuthException("Incorrect password");
    }
  }

  public JwtResponse getAccessToken(@NonNull String refreshToken) {
    if (jwtProvider.validateRefreshToken(refreshToken)) {
      final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
      final String login = claims.getSubject();
      final String saveRefreshToken = refreshStorage.get(login);
      if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
        final User user =
            userService.getByLogin(login).orElseThrow(() -> new AuthException("User not found"));
        final String accessToken = jwtProvider.generateAccessToken(user);
        return new JwtResponse(accessToken, null);
      }
    }
    return new JwtResponse(null, null);
  }

  public JwtResponse refresh(@NonNull String refreshToken) {
    if (jwtProvider.validateRefreshToken(refreshToken)) {
      final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
      final String login = claims.getSubject();
      final String saveRefreshToken = refreshStorage.get(login);
      if(saveRefreshToken != null && saveRefreshToken.equals(refreshToken)){
        final  User user = userService.getByLogin(login)
            .orElseThrow(() -> new AuthException("User not found"));
        final String accessToken = jwtProvider.generateAccessToken(user);
        final String newRefreshToken = jwtProvider.generateRefreshToken(user);
        refreshStorage.put(user.getLogin(), newRefreshToken);
        return new JwtResponse(accessToken, newRefreshToken);
      }
    }
    throw new AuthException("JWT Token is invalid");
  }

  public JwtAuthentication getAuthInfo() {
    return (JwtAuthentication) SecurityContextHolder.getContext().getAuthentication();
  }
}
