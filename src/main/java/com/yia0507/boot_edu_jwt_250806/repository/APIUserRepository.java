package com.yia0507.boot_edu_jwt_250806.repository;

import com.yia0507.boot_edu_jwt_250806.domain.APIUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface APIUserRepository extends JpaRepository<APIUser, String> {
}
