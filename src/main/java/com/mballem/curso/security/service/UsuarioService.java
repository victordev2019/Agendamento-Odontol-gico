package com.mballem.curso.security.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mballem.curso.security.domain.Perfil;
import com.mballem.curso.security.domain.Usuario;
import com.mballem.curso.security.repository.UsuarioRepository;

/*Spring security irá identificar que o usuário está tentando fazer login na aplicação
 * Vai pegar as credenciais e procurar a implementação da classe userDetailsService
 * que tenha o método loadUserByUsername. Então encontra o método e pega a crencial do login
 * username e passar como argumento para a implementação e faz a consulta no banco de dados
 * pelo userName e vai retornar o usuário referente aquele e-mail.
 * 
 * O Spring securty já testa se a senha é válida e vai testar se o perfil do usuário tem a 
 * permissão para aquele tipo de acesso.
 */
@Service
public class UsuarioService implements UserDetailsService{

	@Autowired
	private UsuarioRepository repository;

	
	public Usuario buscarPorEmail(String email) {
		
		return repository.findByEmail(email);
	}

	@Override @Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = buscarPorEmail(username);
		return new User(
				usuario.getEmail() ,
				usuario.getSenha() ,
				AuthorityUtils.createAuthorityList(getAuthorities(usuario.getPerfis()))
				);
	}
	
	private String[] getAuthorities(List<Perfil> perfis) {
		String[] authorities = new String[perfis.size()];
		for(int i = 0; i < perfis.size(); i++) {
			authorities[i] = perfis.get(i).getDesc();
		}
		
		return authorities;
	}
}
