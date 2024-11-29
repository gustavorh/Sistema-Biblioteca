package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.BookMapper;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcBookRepository implements IRepository<Book> {
    private final Connection connection;
    private final IRowMapper<Book> bookMapper;

    public JdbcBookRepository(Connection connection) {
        this.connection = connection;
        this.bookMapper = new BookMapper();
    }
    // SQL Queries as constants.
    private static final String FIND_ALL =
            "SELECT L.id_libro, L.titulo, A.id_autor, A.nombre_completo AS autor, L.isbn, L.año_publicacion, C.id_categoria, C.nombre AS categoria " +
            "FROM Libros L " +
                "INNER JOIN Autores A ON L.id_autor = A.id_autor " +
                "INNER JOIN Categorias C ON L.id_categoria = C.id_categoria " +
            "ORDER BY L.id_libro";

    private static final String FIND_BY_ID =
            "SELECT L.id_libro,L.titulo, A.id_autor, A.nombre_completo AS autor, L.isbn, L.año_publicacion, C.id_categoria, C.nombre AS categoria "+
            "FROM Libros L " +
                    "INNER JOIN Autores A ON L.id_autor = A.id_autor " +
                    "INNER JOIN Categorias C ON L.id_categoria = C.id_categoria " +
            "WHERE L.id_libro = ?";

    private static final String UPDATE_BY_ID =
            "UPDATE Libros SET titulo = ?, id_autor = ?, isbn = ?, año_publicacion = ?, id_categoria = ? " +
            "WHERE id_libro = ?";

    private static final String INSERT =
            "INSERT INTO Libros (titulo, id_autor, isbn, año_publicacion, id_categoria) " +
            "VALUES (?, ?, ?, ?, ?)";

    private static final String DELETE =
            "DELETE FROM Libros " +
            "WHERE id_libro = ?";

    @Override
    public Optional<Book> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(bookMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<Book> findAll() throws SQLException {
        List<Book> books = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                books.add(bookMapper.mapRow(rs));
            }
        }
        return books;
    }

    @Override
    public void save(Book entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, entity.getTitle());
            ps.setLong(2, entity.getAuthor().getAuthorId());
            ps.setString(3, entity.getIsbn());
            ps.setInt(4, entity.getPublicationYear());
            ps.setLong(5, entity.getCategory().getCategoryId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating book failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setBookId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating book failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(Book entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setString(1, entity.getTitle());
            ps.setLong(2, entity.getAuthor().getAuthorId());
            ps.setString(3, entity.getIsbn());
            ps.setInt(4, entity.getPublicationYear());
            ps.setLong(5, entity.getCategory().getCategoryId());
            ps.setLong(6, entity.getBookId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating book failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting book failed, no rows affected.");
            }
        }
    }
}
