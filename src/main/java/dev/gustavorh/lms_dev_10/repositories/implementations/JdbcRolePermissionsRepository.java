package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.RolePermissions;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.RolePermissionsMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcRolePermissionsRepository implements IRepository<RolePermissions> {
    private final Connection connection;
    private final IRowMapper<RolePermissions> rolePermissionsRowMapper;

    public JdbcRolePermissionsRepository(Connection connection) {
        this.connection = connection;
        this.rolePermissionsRowMapper = new RolePermissionsMapper();
    }

    private static final String FIND_ALL =
            "SELECT rp.*, r.nombre AS nombre_rol, p.nombre AS nombre_permiso " +
                    "FROM Roles_Permisos rp " +
                    "INNER JOIN Roles r ON r.id_rol = rp.id_rol " +
                    "INNER JOIN Permisos p ON p.id_permiso = rp.id_permiso " +
                    "ORDER BY id_rol";

    private static final String FIND_BY_ID =
            "SELECT rp.*, r.nombre AS nombre_rol, p.nombre AS nombre_permiso " +
                    "FROM Roles_Permisos rp " +
                    "INNER JOIN Roles r ON r.id_rol = rp.id_rol " +
                    "INNER JOIN Permisos p ON p.id_permiso = rp.id_permiso " +
                    "WHERE rp.id_rol = ? " +
                    "ORDER BY id_rol" ;

    private static final String UPDATE_BY_ID =
            "UPDATE Roles_Permisos SET id_rol = ?, id_permiso = ?" +
                    "WHERE id_rol = ?";

    private static final String INSERT =
            "INSERT INTO Roles_Permisos (id_rol, id_permiso) " +
                    "VALUES (?, ?)";

    private static final String DELETE =
            "DELETE FROM Roles_Permisos WHERE id_rol = ?";

    @Override
    public Optional<RolePermissions> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(rolePermissionsRowMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<RolePermissions> findAll() throws SQLException {
        List<RolePermissions> rolePermissions = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                rolePermissions.add(rolePermissionsRowMapper.mapRow(rs));
            }
        }
        return rolePermissions;
    }

    @Override
    public void save(RolePermissions entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, entity.getRole().getRoleId());
            ps.setLong(2, entity.getPermission().getPermissionId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating RolePermission failed, no rows affected.");
            }
        }
    }

    @Override
    public void update(RolePermissions entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setLong(1, entity.getRole().getRoleId());
            ps.setLong(2, entity.getPermission().getPermissionId());
            ps.setLong(3, entity.getRole().getRoleId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating RolePermission failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting RolePermission failed, no rows affected.");
            }
        }
    }
}
