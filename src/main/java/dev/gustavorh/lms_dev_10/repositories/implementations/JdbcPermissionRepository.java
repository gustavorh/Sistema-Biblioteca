package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.Permission;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.PermissionMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcPermissionRepository implements IRepository<Permission> {
    private final Connection connection;
    private final IRowMapper<Permission> permissionMapper;

    public JdbcPermissionRepository(Connection connection) {
        this.connection = connection;
        this.permissionMapper = new PermissionMapper();
    }

    private static final String FIND_ALL = "SELECT * FROM Permisos";
    private static final String FIND_BY_ID = "SELECT * FROM Permisos WHERE id_permiso = ?";
    private static final String UPDATE_BY_ID = "UPDATE Permisos SET nombre = ?, descripcion = ? WHERE id_permiso = ?";
    private static final String INSERT = "INSERT INTO Permisos (nombre, descripcion) VALUES (?, ?)";
    private static final String DELETE = "DELETE FROM Permisos WHERE id_permiso = ?";

    @Override
    public Optional<Permission> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(permissionMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<Permission> findAll() throws SQLException {
        List<Permission> permissions = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                permissions.add(permissionMapper.mapRow(rs));
            }
        }
        return permissions;
    }

    @Override
    public void save(Permission entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, entity.getName());
            ps.setString(2, entity.getDescription());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating permission failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setPermissionId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating permission failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(Permission entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setString(1, entity.getName());
            ps.setString(2, entity.getDescription());
            ps.setLong(3, entity.getPermissionId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating permission failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting permission failed, no rows affected.");
            }
        }
    }
}
