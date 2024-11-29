package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.User;

import java.sql.ResultSet;
import java.sql.SQLException;

public class UserMapper implements IRowMapper<User> {
    @Override
    public User mapRow(ResultSet rs) throws SQLException {
        User user = new User();
        user.setUserId(rs.getLong("id_usuario"));
        user.setUserName(rs.getString("usuario"));
        user.setPassword(rs.getString("clave"));
        return user;
    }
}
