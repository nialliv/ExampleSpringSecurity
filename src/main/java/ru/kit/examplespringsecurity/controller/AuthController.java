package ru.kit.examplespringsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.kit.examplespringsecurity.model.JwtRequest;
import ru.kit.examplespringsecurity.model.JwtResponse;
import ru.kit.examplespringsecurity.model.RefreshJwtRequest;
import ru.kit.examplespringsecurity.service.AuthService;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class AuthController {
  private final AuthService authService;

  @PostMapping("login")
  public JwtResponse login(@RequestBody JwtRequest authRequest) {
    return authService.login(authRequest);
  }

  @PostMapping("token")
  public JwtResponse getNewAccessToken(@RequestBody RefreshJwtRequest request) {
    return authService.getAccessToken(request.getRefreshToken());
  }

  @PostMapping("refresh")
  public JwtResponse getNewRefreshToken(@RequestBody RefreshJwtRequest request) {
    return authService.refresh(request.getRefreshToken());
  }
}
