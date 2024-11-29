package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Author;
import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.entities.Category;

import java.sql.ResultSet;
import java.sql.SQLException;


public class BookMapper implements IRowMapper<Book> {

    @Override
    public Book mapRow(ResultSet rs) throws SQLException {
        Book book = new Book();
        book.setBookId(rs.getLong("id_libro"));
        book.setTitle(rs.getString("titulo"));
        book.setIsbn(rs.getString("isbn"));
        book.setPublicationYear(rs.getInt("año_publicacion"));

        // Map the Author
        Author author = new Author();
        author.setAuthorId(rs.getLong("id_autor"));
        author.setFullName(rs.getString("autor"));
        book.setAuthor(author);

        // Map the Category
        Category category = new Category();
        category.setCategoryId(rs.getLong("id_categoria"));
        category.setName(rs.getString("categoria"));
        book.setCategory(category);

        return book;
    }
}
