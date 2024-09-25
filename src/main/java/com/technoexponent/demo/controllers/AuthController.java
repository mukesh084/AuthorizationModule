package com.technoexponent.demo.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.technoexponent.demo.model.ERole;
import com.technoexponent.demo.model.Role;
import com.technoexponent.demo.model.User;
import com.technoexponent.demo.repository.RoleRepository;
import com.technoexponent.demo.repository.UserRepository;
import com.technoexponent.demo.request.LoginRequest;
import com.technoexponent.demo.request.SignupRequest;
import com.technoexponent.demo.response.JwtResponse;
import com.technoexponent.demo.response.MessageResponse;
import com.technoexponent.demo.security.jwt.JwtUtils;
import com.technoexponent.demo.security.services.UserDetailsImpl;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/auth")
public class AuthController {
	
	
	@Autowired
	  AuthenticationManager authenticationManager;

	  @Autowired
	  UserRepository userRepository;

	  @Autowired
	  RoleRepository roleRepository;

	  @Autowired
	  PasswordEncoder encoder;

	  @Autowired
	  JwtUtils jwtUtils;

	  @PostMapping("/login")
	  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

	    Authentication authentication = authenticationManager.authenticate(
	        new UsernamePasswordAuthenticationToken(loginRequest.getName(), loginRequest.getPassword()));

	    SecurityContextHolder.getContext().setAuthentication(authentication);
	    String jwt = jwtUtils.generateJwtToken(authentication);
	    
	    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();    
	    List<String> roles = userDetails.getAuthorities().stream()
	        .map(item -> item.getAuthority())
	        .collect(Collectors.toList());

	    return ResponseEntity.ok(new JwtResponse(jwt, 
	                         userDetails.getId(), 
	                         userDetails.getUsername(), 
	                         userDetails.getEmail(), 
	                         roles));
	  }

	  @PostMapping("/adminRegistration")
	  public ResponseEntity<?> adminRegistration(@Valid @RequestBody SignupRequest signUpRequest) {
	    if (userRepository.existsByName(signUpRequest.getName())) {
	      return ResponseEntity
	          .badRequest()
	          .body(new MessageResponse("Error: name is already taken!"));
	    }

	    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
	      return ResponseEntity
	          .badRequest()
	          .body(new MessageResponse("Error: Email is already in use!"));
	    }

	    // Create new user's account
	    User user = new User(signUpRequest.getName(), 
	               signUpRequest.getEmail(),
	               encoder.encode(signUpRequest.getPassword()));
	    
	    Set<Role> roles = new HashSet<>();
	    Optional<Role> adminRole = roleRepository.findByName(ERole.ROLE_ADMIN);
	    roles.add(adminRole.get());

	    user.setRoles(roles);
	    userRepository.save(user);

	    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	  }

}
