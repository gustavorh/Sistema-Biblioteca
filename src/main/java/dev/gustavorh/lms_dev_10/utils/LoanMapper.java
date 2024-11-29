package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.entities.Loan;
import dev.gustavorh.lms_dev_10.entities.Member;

import java.sql.ResultSet;
import java.sql.SQLException;

public class LoanMapper implements IRowMapper<Loan> {
    @Override
    public Loan mapRow(ResultSet rs) throws SQLException {
        Loan loan = new Loan();
        loan.setLoanId(rs.getLong("id_prestamo"));

        Book book = new Book();
        book.setBookId(rs.getLong("id_libro"));
        book.setTitle(rs.getString("titulo"));
        loan.setBook(book);

        Member member = new Member();
        member.setMemberId(rs.getLong("id_miembro"));
        member.setName(rs.getString("nombre"));
        member.setPaternalSurname(rs.getString("apellido_paterno"));
        member.setMaternalSurname(rs.getString("apellido_materno"));
        loan.setMember(member);

        loan.setLoanDate(rs.getTimestamp("fecha_desde").toLocalDateTime());
        loan.setDueDate(rs.getTimestamp("fecha_hasta").toLocalDateTime());
        loan.setReturnDate(rs.getTimestamp("fecha_devolucion").toLocalDateTime());

        return loan;
    }
}
