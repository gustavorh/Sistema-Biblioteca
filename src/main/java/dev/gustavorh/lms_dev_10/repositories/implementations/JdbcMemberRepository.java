package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.Member;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.MemberMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcMemberRepository implements IRepository<Member> {
    private final Connection connection;
    private final IRowMapper<Member> memberMapper;

    public JdbcMemberRepository(Connection connection) {
        this.connection = connection;
        this.memberMapper = new MemberMapper();
    }

    private static final String FIND_ALL =
            "SELECT m.*, u.usuario, e.nombre AS estado " +
            "FROM Miembros m " +
            "INNER JOIN Usuarios u ON m.id_usuario = u.id_usuario " +
            "INNER JOIN Estados e ON m.id_estado = e.id_estado " +
            "ORDER BY m.id_miembro";
    private static final String FIND_BY_ID = "SELECT m.*, u.usuario, e.nombre AS estado " +
            "FROM Miembros m " +
            "INNER JOIN Usuarios u ON m.id_usuario = u.id_usuario " +
            "INNER JOIN Estados e ON m.id_estado = e.id_estado " +
            "WHERE m.id_miembro = ? ORDER BY m.id_miembro";
    private static final String UPDATE_BY_ID = "UPDATE Miembros SET RUT = ?, id_usuario = ?, nombre = ?, apellido_paterno = ?, apellido_materno = ?, fecha_inscripcion = ?, id_estado = ? WHERE id_miembro = ?";
    private static final String INSERT = "INSERT INTO Miembros (RUT, id_usuario, nombre, apellido_paterno, apellido_materno, fecha_inscripcion, id_estado) VALUES (?, ?, ?, ?, ?, ?, ?)";
    private static final String DELETE = "DELETE FROM Miembros WHERE id_miembro = ?";

    @Override
    public Optional<Member> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(memberMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<Member> findAll() throws SQLException {
        List<Member> members = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                members.add(memberMapper.mapRow(rs));
            }
        }
        return members;
    }

    @Override
    public void save(Member entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, entity.getRut());
            ps.setLong(2, entity.getUser().getUserId());
            ps.setString(3, entity.getName());
            ps.setString(4, entity.getPaternalSurname());
            ps.setString(5, entity.getMaternalSurname());
            ps.setTimestamp(6, Timestamp.valueOf(entity.getRegistrationDate()));
            ps.setLong(7, entity.getStatus().getStatusId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating member failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setMemberId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating member failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(Member entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setString(1, entity.getRut());
            ps.setLong(2, entity.getUser().getUserId());
            ps.setString(3, entity.getName());
            ps.setString(4, entity.getPaternalSurname());
            ps.setString(5, entity.getMaternalSurname());
            ps.setTimestamp(6, Timestamp.valueOf(entity.getRegistrationDate()));
            ps.setLong(7, entity.getStatus().getStatusId());
            ps.setLong(8, entity.getMemberId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating member failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting member failed, no rows affected.");
            }
        }
    }
}
