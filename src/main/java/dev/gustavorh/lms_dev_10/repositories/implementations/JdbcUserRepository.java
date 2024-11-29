package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.User;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IUserRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.UserMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcUserRepository implements IUserRepository {
    private final Connection connection;
    private final IRowMapper<User> userMapper;

    public JdbcUserRepository(Connection connection) {
        this.connection = connection;
        this.userMapper = new UserMapper();
    }

    private static final String FIND_ALL = "SELECT * FROM Usuarios ORDER BY id_usuario ASC";
    private static final String FIND_BY_ID = "SELECT * FROM Usuarios WHERE id_usuario = ?";
    private static final String FIND_BY_USER_NAME = "SELECT * FROM Usuarios WHERE usuario = ?";
    private static final String UPDATE_BY_ID = "UPDATE Usuarios SET usuario = ?, clave = ? WHERE id_usuario = ?";
    private static final String INSERT = "INSERT INTO Usuarios (usuario, clave) VALUES (?, ?)";
    private static final String DELETE = "DELETE FROM Usuarios WHERE id_usuario = ?";
    private static final String UPDATE_ROLE_BY_ID = "UPDATE Roles_Usuarios SET id_rol = ? WHERE id_usuario = ?";

    @Override
    public User findByUserName(String userName) throws SQLException {
        User user = null;
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_USER_NAME)) {
            ps.setString(1, userName);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    user = userMapper.mapRow(rs);
                }
            }
        }
        return user;
    }

    @Override
    public void updateRole(Long userId, Long roleId) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_ROLE_BY_ID, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, userId);
            ps.setLong(2, roleId);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating user role failed, no rows affected.");
            }
        }

    }

    @Override
    public Optional<User> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(userMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<User> findAll() throws SQLException {
        List<User> users = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                users.add(userMapper.mapRow(rs));
            }
        }
        return users;
    }

    @Override
    public void save(User entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, entity.getUserName());
            ps.setString(2, entity.getPassword());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating user failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setUserId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating user failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(User entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setString(1, entity.getUserName());
            ps.setString(2, entity.getPassword());
            ps.setLong(3, entity.getUserId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating user failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting user failed, no rows affected.");
            }
        }
    }
}
