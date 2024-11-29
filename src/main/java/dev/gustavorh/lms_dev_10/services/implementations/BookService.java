package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class BookService implements IService<Book> {
    private final IRepository<Book> bookRepository;

    public BookService(IRepository<Book> bookRepository) {
        this.bookRepository = bookRepository;
    }

    @Override
    public Optional<Book> findById(Long id) {
        try {
            Optional<Book> bookOptional = bookRepository.findById(id);
            if (bookOptional.isPresent()) {
                return bookOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving book with id: " + id, e);
        }
    }

    @Override
    public List<Book> findAll() {
        try {
            return bookRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all books", e);
        }
    }

    @Override
    public void save(Book entity) {
        try {
            bookRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving book", e);
        }
    }

    @Override
    public void update(Book entity) {
        try {
            if (bookRepository.findById(entity.getBookId()).isPresent()) {
                bookRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating book", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (bookRepository.findById(id).isPresent()) {
                bookRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting book with id: " + id, e);
        }
    }
}
