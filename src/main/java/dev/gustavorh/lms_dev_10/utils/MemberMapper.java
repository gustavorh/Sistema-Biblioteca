package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Member;
import dev.gustavorh.lms_dev_10.entities.Status;
import dev.gustavorh.lms_dev_10.entities.User;

import java.sql.ResultSet;
import java.sql.SQLException;

public class MemberMapper implements IRowMapper<Member> {
    @Override
    public Member mapRow(ResultSet rs) throws SQLException {
        Member member = new Member();
        member.setMemberId(rs.getLong("id_miembro"));
        member.setRut(rs.getString("RUT"));

        // Relación -> User
        User user = new User();
        user.setUserId(rs.getLong("id_usuario"));
        user.setUserName(rs.getString("usuario"));
        member.setUser(user);

        // Substring at every space character to get the name, paternalSurname, maternalSurname attributes.
        member.setName(rs.getString("nombre"));
        member.setPaternalSurname(rs.getString("apellido_paterno"));
        member.setMaternalSurname(rs.getString("apellido_materno"));

        member.setRegistrationDate(rs.getTimestamp("fecha_inscripcion").toLocalDateTime());

        Status status = new Status();
        status.setStatusId(rs.getLong("id_estado"));
        status.setName(rs.getString("estado"));
        member.setStatus(status);

        return member;
    }
}
