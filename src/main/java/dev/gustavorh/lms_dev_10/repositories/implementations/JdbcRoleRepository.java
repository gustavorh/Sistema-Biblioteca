package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.RoleMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcRoleRepository implements IRepository<Role> {
    private final Connection connection;
    private final IRowMapper<Role> roleMapper;

    public JdbcRoleRepository(Connection connection) {
        this.connection = connection;
        this.roleMapper = new RoleMapper();
    }

    private static final String FIND_ALL = "SELECT * FROM Roles";
    private static final String FIND_BY_ID = "SELECT * FROM Roles WHERE id_rol = ?";
    private static final String UPDATE_BY_ID = "UPDATE Roles SET nombre = ?, descripcion = ? WHERE id_rol = ?";
    private static final String INSERT = "INSERT INTO Roles (nombre, descripcion) VALUES (?, ?)";
    private static final String DELETE = "DELETE FROM Roles WHERE id_rol = ?";

    @Override
    public Optional<Role> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(roleMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<Role> findAll() throws SQLException {
        List<Role> roles = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                roles.add(roleMapper.mapRow(rs));
            }
        }
        return roles;
    }

    @Override
    public void save(Role entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, entity.getName());
            ps.setString(2, entity.getDescription());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating role failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setRoleId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating role failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(Role entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setString(1, entity.getName());
            ps.setString(2, entity.getDescription());
            ps.setLong(3, entity.getRoleId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating role failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting role failed, no rows affected.");
            }
        }
    }
}
