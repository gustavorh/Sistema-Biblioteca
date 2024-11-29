package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.RoleUsers;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.RoleUsersMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcRoleUsersRepository implements IRepository<RoleUsers> {
    private final Connection connection;
    private final IRowMapper<RoleUsers> roleUsersMapper;

    public JdbcRoleUsersRepository(Connection connection) {
        this.connection = connection;
        this.roleUsersMapper = new RoleUsersMapper();
    }

    private static final String FIND_ALL =
            "SELECT ru.*, r.nombre AS nombre_rol, u.usuario " +
                    "FROM Roles_Usuarios ru " +
                    "INNER JOIN Roles r ON r.id_rol = ru.id_rol " +
                    "INNER JOIN Usuarios u ON u.id_usuario = ru.id_usuario " +
                    "ORDER BY id_rol";

    private static final String FIND_BY_ID =
            "SELECT ru.*, r.nombre AS nombre_rol, u.usuario " +
                    "FROM Roles_Usuarios ru " +
                    "INNER JOIN Roles r ON r.id_rol = ru.id_rol " +
                    "INNER JOIN Usuarios u ON u.id_usuario = ru.id_usuario " +
                    "WHERE ru.id_rol = ?" +
                    "ORDER BY id_rol";

    private static final String UPDATE_BY_ID =
            "UPDATE Roles_Usuarios SET id_rol = ?, id_usuario = ? " +
                    "WHERE id_rol = ?";

    private static final String INSERT =
            "INSERT INTO Roles_Usuarios (id_rol, id_usuario) " +
                    "VALUES (?, ?)";

    private static final String DELETE =
            "DELETE FROM Roles_Usuarios WHERE id_rol = ?";

    @Override
    public Optional<RoleUsers> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(roleUsersMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<RoleUsers> findAll() throws SQLException {
        List<RoleUsers> loans = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                loans.add(roleUsersMapper.mapRow(rs));
            }
        }
        return loans;
    }

    @Override
    public void save(RoleUsers entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, entity.getRole().getRoleId());
            ps.setLong(2, entity.getUser().getUserId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating RoleUser failed, no rows affected.");
            }
        }
    }

    @Override
    public void update(RoleUsers entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setLong(1, entity.getRole().getRoleId());
            ps.setLong(2, entity.getUser().getUserId());
            ps.setLong(3, entity.getRole().getRoleId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating RoleUser failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting RoleUser failed, no rows affected.");
            }
        }
    }
}
