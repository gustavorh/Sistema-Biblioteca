package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.Author;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.AuthorMapper;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcAuthorRepository implements IRepository<Author> {
    private final Connection connection;
    private final IRowMapper<Author> authorMapper;

    public JdbcAuthorRepository(Connection connection) {
        this.connection = connection;
        this.authorMapper = new AuthorMapper();
    }

    private static final String FIND_ALL = "SELECT * FROM Autores ORDER BY id_autor";
    private static final String FIND_BY_ID = "SELECT * FROM Autores WHERE id_autor = ?";
    private static final String UPDATE_BY_ID = "UPDATE Autores SET nombre = ?, apellido = ?, nombre_completo = ? WHERE id_autor = ?";
    private static final String INSERT = "INSERT INTO Autores (nombre, apellido, nombre_completo) VALUES (?, ?, ?)";
    private static final String DELETE = "DELETE FROM Autores WHERE id_autor = ?";

    @Override
    public Optional<Author> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(authorMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<Author> findAll() throws SQLException {
        List<Author> authors = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                authors.add(authorMapper.mapRow(rs));
            }
        }
        return authors;
    }

    @Override
    public void save(Author entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, entity.getName());
            ps.setString(2, entity.getSurname());
            ps.setString(3, entity.getFullName());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating author failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setAuthorId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating author failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(Author entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setString(1, entity.getName());
            ps.setString(2, entity.getSurname());
            ps.setString(3, entity.getFullName());
            ps.setLong(4, entity.getAuthorId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating author failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting author failed, no rows affected.");
            }
        }
    }
}
