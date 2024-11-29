package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Author;

import java.sql.ResultSet;
import java.sql.SQLException;

public class AuthorMapper implements IRowMapper<Author> {
    @Override
    public Author mapRow(ResultSet rs) throws SQLException {
        Author author = new Author();
        author.setAuthorId(rs.getLong("id_autor"));
        author.setName(rs.getString("nombre"));
        author.setSurname(rs.getString("apellido"));
        author.setFullName(rs.getString("nombre_completo"));
        return author;
    }
}