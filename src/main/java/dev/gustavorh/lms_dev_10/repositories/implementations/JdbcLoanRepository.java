package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.entities.Loan;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.utils.IRowMapper;
import dev.gustavorh.lms_dev_10.utils.LoanMapper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JdbcLoanRepository implements IRepository<Loan> {
    private final Connection connection;
    private final IRowMapper<Loan> loanMapper;

    public JdbcLoanRepository(Connection connection) {
        this.connection = connection;
        this.loanMapper = new LoanMapper();
    }

    private static final String FIND_ALL =
            "SELECT p.*, l.titulo, m.nombre, m.apellido_paterno, m.apellido_materno " +
                    "FROM Prestamos p " +
                    "INNER JOIN Libros l ON l.id_libro = p.id_libro " +
                    "INNER JOIN Miembros m ON m.id_miembro = p.id_miembro " +
                    "ORDER BY p.id_prestamo";

    private static final String FIND_BY_ID =
            "SELECT p.*, l.titulo, m.nombre, m.apellido_paterno, m.apellido_materno " +
                    "FROM Prestamos p " +
                    "INNER JOIN Libros l ON l.id_libro = p.id_libro " +
                    "INNER JOIN Miembros m ON m.id_miembro = p.id_miembro " +
                    "WHERE p.id_prestamo = ?" +
                    "ORDER BY p.id_prestamo" ;

    private static final String UPDATE_BY_ID =
            "UPDATE Prestamos SET id_libro = ?, id_miembro = ?, fecha_desde = ?, fecha_hasta = ?, fecha_devolucion = ? " +
                    "WHERE id_prestamo = ?";

    private static final String INSERT =
            "INSERT INTO Prestamos (id_libro, id_miembro, fecha_desde, fecha_hasta, fecha_devolucion) " +
                    "VALUES (?, ?, ?, ?, ?)";

    private static final String DELETE =
            "DELETE FROM Prestamos WHERE id_prestamo = ?";

    @Override
    public Optional<Loan> findById(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(FIND_BY_ID)) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(loanMapper.mapRow(rs));
                }
            }
            return Optional.empty();
        }
    }

    @Override
    public List<Loan> findAll() throws SQLException {
        List<Loan> loans = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(FIND_ALL)) {
            while (rs.next()) {
                loans.add(loanMapper.mapRow(rs));
            }
        }
        return loans;
    }

    @Override
    public void save(Loan entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(INSERT, Statement.RETURN_GENERATED_KEYS)) {
            ps.setLong(1, entity.getBook().getBookId());
            ps.setLong(2, entity.getMember().getMemberId());
            ps.setTimestamp(3, Timestamp.valueOf(entity.getLoanDate()));
            ps.setTimestamp(4, Timestamp.valueOf(entity.getDueDate()));
            ps.setTimestamp(5, Timestamp.valueOf(entity.getReturnDate()));

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating loan failed, no rows affected.");
            }

            try (ResultSet generatedKeys = ps.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entity.setLoanId(generatedKeys.getLong(1));
                } else {
                    throw new SQLException("Creating loan failed, no ID obtained.");
                }
            }
        }
    }

    @Override
    public void update(Loan entity) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(UPDATE_BY_ID)) {
            ps.setLong(1, entity.getBook().getBookId());
            ps.setLong(2, entity.getMember().getMemberId());
            ps.setTimestamp(3, Timestamp.valueOf(entity.getLoanDate()));
            ps.setTimestamp(4, Timestamp.valueOf(entity.getDueDate()));
            ps.setTimestamp(5, Timestamp.valueOf(entity.getReturnDate()));
            ps.setLong(6, entity.getLoanId());

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Updating loan failed, no rows affected.");
            }
        }
    }

    @Override
    public void delete(Long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(DELETE)) {
            ps.setLong(1, id);

            int affectedRows = ps.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Deleting loan failed, no rows affected.");
            }
        }
    }
}
