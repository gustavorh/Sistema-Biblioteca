package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.entities.RoleUsers;
import dev.gustavorh.lms_dev_10.entities.User;

import java.sql.ResultSet;
import java.sql.SQLException;

public class RoleUsersMapper implements IRowMapper<RoleUsers> {
    @Override
    public RoleUsers mapRow(ResultSet rs) throws SQLException {
        RoleUsers roleUsers = new RoleUsers();
        Role role = new Role();
        User user = new User();

        role.setRoleId(rs.getLong("id_rol"));
        role.setName(rs.getString("nombre_rol"));
        user.setUserId(rs.getLong("id_usuario"));
        user.setUserName(rs.getString("usuario"));

        roleUsers.setRole(role);
        roleUsers.setUser(user);

        return roleUsers;
    }
}
