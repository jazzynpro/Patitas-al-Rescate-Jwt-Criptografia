package com.krakedev.jwt.controller;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioServices;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final UsuarioServices service;

	public AuthController(UsuarioServices service) {
		super();
		this.service = service;
	}

	@PostMapping("/registrar")
	public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {
		try {
			Usuario usuarioNuevo = service.registrar(usuario);
			usuarioNuevo.setPassword(null);
			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);

		} catch (IllegalArgumentException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		}
	}

	public ResponseEntity<?> login(@RequestBody Usuario datosLogin) {
		Optional<Usuario> usuario = service.login(datosLogin.getUserName(), datosLogin.getPassword());
		if (usuario.isPresent()) {
			Usuario usuarioAutenticado = usuario.get();
			// No devolver la contraseña en la respuesta
			usuarioAutenticado.setPassword(null);
			return ResponseEntity.ok(usuarioAutenticado);
		}
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrectos");
	}

}
