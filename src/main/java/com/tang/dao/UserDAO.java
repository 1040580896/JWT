package com.tang.dao;

import com.tang.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserDAO {
    User login(User user);
}
