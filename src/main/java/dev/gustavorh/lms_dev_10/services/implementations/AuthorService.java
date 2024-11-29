package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Author;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class AuthorService implements IService<Author> {
    private final IRepository<Author> authorRepository;

    public AuthorService(IRepository<Author> authorRepository) {
        this.authorRepository = authorRepository;
    }

    @Override
    public Optional<Author> findById(Long id) {
        try {
            return authorRepository.findById(id);
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving author with id: " + id, e);
        }
    }

    @Override
    public List<Author> findAll() {
        try {
            return authorRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all authors", e);
        }
    }

    @Override
    public void save(Author entity) {
        try {
            authorRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving author", e);
        }
    }

    @Override
    public void update(Author entity) {
        try {
            authorRepository.update(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error updating author", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            authorRepository.delete(id);
        } catch (SQLException e) {
            throw new ServiceException("Error deleting author with id: " + id, e);
        }
    }
}
