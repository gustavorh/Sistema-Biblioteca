package dev.gustavorh.lms_dev_10.repositories.implementations;

import dev.gustavorh.lms_dev_10.dtos.MemberActivityReportDTO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class MemberActivityReportRepository {
    private final Connection connection;

    public MemberActivityReportRepository(Connection connection) {
        this.connection = connection;
    }

    private static final String QUERY =
            "SELECT  " +
                    "    m.id_miembro, " +
                    "    m.RUT, " +
                    "    CONCAT(m.nombre, ' ', m.apellido_paterno, ' ', m.apellido_materno) AS 'Nombre Completo', " +
                    "    e.nombre AS 'Estado', " +
                    "    m.fecha_inscripcion AS 'Fecha Inscripción', " +
                    "    COUNT(p.id_prestamo) AS 'Total Préstamos Históricos', " +
                    "    SUM(CASE  " +
                    "        WHEN p.fecha_devolucion > p.fecha_hasta THEN 1  " +
                    "        ELSE 0  " +
                    "    END) AS 'Préstamos Atrasados', " +
                    "    (SELECT COUNT(*) " +
                    "     FROM Prestamos p2 " +
                    "     WHERE p2.id_miembro = m.id_miembro " +
                    "     AND GETDATE() BETWEEN p2.fecha_desde AND p2.fecha_hasta) AS 'Préstamos Activos' " +
                    "FROM  " +
                    "    Miembros m " +
                    "    INNER JOIN Estados e ON m.id_estado = e.id_estado " +
                    "    LEFT JOIN Prestamos p ON m.id_miembro = p.id_miembro " +
                    "GROUP BY  " +
                    "    m.id_miembro, " +
                    "    m.RUT, " +
                    "    m.nombre, " +
                    "    m.apellido_paterno, " +
                    "    m.apellido_materno, " +
                    "    e.nombre, " +
                    "    m.fecha_inscripcion, " +
                    "    m.id_miembro " +
                    "ORDER BY  " +
                    "    N'Total Préstamos Históricos' DESC";

    public List<MemberActivityReportDTO> getActivityReport() throws SQLException {
        List<MemberActivityReportDTO> members = new ArrayList<>();

        try (PreparedStatement ps = connection.prepareStatement(QUERY)) {
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    MemberActivityReportDTO report = new MemberActivityReportDTO(
                            rs.getLong("id_miembro"),
                            rs.getString("RUT"),
                            rs.getString("Nombre Completo"),
                            rs.getString("Estado"),
                            rs.getTimestamp("Fecha Inscripción").toLocalDateTime(),
                            rs.getInt("Total Préstamos Históricos"),
                            rs.getInt("Préstamos Atrasados"),
                            rs.getInt("Préstamos Activos")
                    );
                    members.add(report);
                }
            }
        }
        return members;
    }
}
