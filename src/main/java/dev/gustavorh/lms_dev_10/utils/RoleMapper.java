package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Role;

import java.sql.ResultSet;
import java.sql.SQLException;

public class RoleMapper implements IRowMapper<Role>{
    @Override
    public Role mapRow(ResultSet rs) throws SQLException {
        Role role = new Role();
        role.setRoleId(rs.getLong("id_rol"));
        role.setName(rs.getString("nombre"));
        role.setDescription(rs.getString("descripcion"));
        return role;
    }
}
