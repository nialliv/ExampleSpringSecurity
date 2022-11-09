package ru.kit.examplespringsecurity.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.kit.examplespringsecurity.model.JwtAuthentication;
import ru.kit.examplespringsecurity.service.AuthService;

@RestController
@RequestMapping("api")
@RequiredArgsConstructor
public class Controller {

  private final AuthService authService;

  @PreAuthorize("hasAnyAuthority('USER')")
  @GetMapping("hello/user")
  public String helloUser() {
    final JwtAuthentication authInfo = authService.getAuthInfo();
    return "Hello user " + authInfo.getPrincipal() + "!";
  }

  @PreAuthorize("hasAuthority('ADMIN')")
  @GetMapping("hello/admin")
  public String helloAdmin() {
    final JwtAuthentication authInfo = authService.getAuthInfo();
    return "Hello admin " + authInfo.getPrincipal() + "!";
  }
}
