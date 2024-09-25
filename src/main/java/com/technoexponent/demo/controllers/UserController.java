package com.technoexponent.demo.controllers;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.technoexponent.demo.dto.UserDto;
import com.technoexponent.demo.model.ERole;
import com.technoexponent.demo.model.Role;
import com.technoexponent.demo.model.User;
import com.technoexponent.demo.repository.RoleRepository;
import com.technoexponent.demo.repository.UserRepository;
import com.technoexponent.demo.request.SignupRequest;
import com.technoexponent.demo.response.MessageResponse;

import jakarta.validation.Valid;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class UserController {
	
	  @Autowired
	  UserRepository userRepository;

	  @Autowired
	  RoleRepository roleRepository;

	  @Autowired
	  PasswordEncoder encoder;
	  

	  @GetMapping("/profile/{name}")
	  @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
	  public UserDto userAccess(@PathVariable("name") String name) {
	    Optional<User> user = userRepository.findByName(name);
	    UserDto userDetail= null; 
	    if(user.isPresent()) {
	    	userDetail = new UserDto(user.get().getName(), user.get().getEmail());
	    }
	    return userDetail;
	  }
	  
	  @PostMapping("/add")
	  @PreAuthorize("hasRole('ROLE_ADMIN')")
	  public ResponseEntity<?> addUser(@Valid @RequestBody SignupRequest signUpRequest) {
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
	    Optional<Role> userRole = roleRepository.findByName(ERole.ROLE_USER);
	    
	    roles.add(userRole.get());
	    
	   
	    user.setRoles(roles);
	    userRepository.save(user);

	    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	  }
}
