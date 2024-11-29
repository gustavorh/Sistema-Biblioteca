package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Permission;
import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.entities.RolePermissions;

import java.sql.ResultSet;
import java.sql.SQLException;

public class RolePermissionsMapper implements IRowMapper<RolePermissions> {
    @Override
    public RolePermissions mapRow(ResultSet rs) throws SQLException {
        RolePermissions rolePermissions = new RolePermissions();
        Role role = new Role();
        role.setRoleId(rs.getLong("id_rol"));
        role.setName(rs.getString("nombre_rol"));
        rolePermissions.setRole(role);
        Permission permission = new Permission();
        permission.setPermissionId(rs.getLong("id_permiso"));
        permission.setName(rs.getString("nombre_permiso"));
        rolePermissions.setPermission(permission);
        return rolePermissions;
    }
}
