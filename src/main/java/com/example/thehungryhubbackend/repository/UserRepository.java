package com.example.thehungryhubbackend.repository;

import com.example.thehungryhubbackend.user.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<UserEntity,Integer> {
    UserEntity findUserByUsername(String username);

    UserEntity findUserByName(String name);
}
