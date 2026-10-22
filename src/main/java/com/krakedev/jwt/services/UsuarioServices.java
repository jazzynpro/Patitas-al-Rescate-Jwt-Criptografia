package com.krakedev.jwt.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repository.UsuarioRepository;

@Service
public class UsuarioServices {
	private final UsuarioRepository repository;

	public UsuarioServices(UsuarioRepository repository) {
		super();
		this.repository = repository;
	}

	public Usuario registrar(Usuario usuario) {
		if (repository.findByUsername(usuario.getUserName()).isPresent()) {
			throw new IllegalArgumentException("El nombre de usuario ya está registrado");
		}
		// Generar el hash de la contraseña
		String passwordHash = BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt());

		// Guardar el hash, no la contraseña original
		usuario.setPassword(passwordHash);
		return repository.save(usuario);

	}

	public Optional<Usuario> login(String username, String password) {

		Optional<Usuario> usuario = repository.findByUsername(username);

		if (usuario.isPresent() && usuario.get().getPassword().equals(password)) {
			return usuario;
		}
		
		if (usuario.isPresent()
                && BCrypt.checkpw(
                    password,
                    usuario.get().getPassword()
                )) {
            return usuario;
        }

		return Optional.empty();
	}

}
