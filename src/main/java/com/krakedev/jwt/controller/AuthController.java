package com.krakedev.jwt.controller;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioServices;
import com.krakedev.jwt.utils.JwtUtil;

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
			// usuarioNuevo.setPassword(null);
			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);

		} catch (IllegalArgumentException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		}
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Usuario datosLogin) {
		Optional<Usuario> usuario = service.login(datosLogin.getUserName(), datosLogin.getPassword());

		if (usuario.isPresent()) {

			Usuario usuarioAutenticado = usuario.get();

			String token = JwtUtil.generarToken(usuarioAutenticado.getUserName(), usuarioAutenticado.getRol());

			return ResponseEntity.ok(java.util.Map.of("token", token, "tipo", "Bearer", "username",
					usuarioAutenticado.getUserName(), "rol", usuarioAutenticado.getRol()));
		}

		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrectos");
	}

	@GetMapping("/perfil")
	public ResponseEntity<?> perfil(@RequestHeader(value = "Authorization", required = false) String authorization) {

		try {
			// Verificar que exista la cabecera Bearer
			if (authorization == null || !authorization.startsWith("Bearer ")) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token no proporcionado");
			}

			// Extraer el token de la cabecera
			String token = authorization.substring(7);

			// Validar la firma y la expiración
			com.auth0.jwt.interfaces.DecodedJWT jwt = JwtUtil.validarToken(token);

			// Obtener los datos del usuario desde el token validado
			String username = jwt.getSubject();
			String rol = jwt.getClaim("rol").asString();

			// Saludo según el rol
			String mensaje;

			if ("ADMIN".equals(rol)) {
				mensaje = "Bienvenido voluntario " + username + ". Tienes acceso como administrador.";
			} else if ("USER".equals(rol)) {
				mensaje = "Bienvenido adoptante " + username + ". Puedes consultar tu perfil.";
			} else {
				mensaje = "Bienvenido " + username;
			}

			return ResponseEntity.ok(java.util.Map.of("username", username, "rol", rol, "mensaje", mensaje));
		} catch (com.auth0.jwt.exceptions.JWTVerificationException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido o expirado");
		}

	}

}
