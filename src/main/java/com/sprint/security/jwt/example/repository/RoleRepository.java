package com.sprint.security.jwt.example.repository;

import java.util.Optional;

import com.sprint.security.jwt.example.model.EnumRole;
import com.sprint.security.jwt.example.model.Role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

	Optional<Role> findByName(EnumRole name);

}