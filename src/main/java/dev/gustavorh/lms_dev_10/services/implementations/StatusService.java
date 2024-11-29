package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Status;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class StatusService implements IService<Status> {
    private final IRepository<Status> statusRepository;

    public StatusService(IRepository<Status> statusRepository) {
        this.statusRepository = statusRepository;
    }

    @Override
    public Optional<Status> findById(Long id) {
        try {
            Optional<Status> statusOptional = statusRepository.findById(id);
            if (statusOptional.isPresent()) {
                return statusOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving status with id: " + id, e);
        }
    }

    @Override
    public List<Status> findAll() {
        try {
            return statusRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all statuses ", e);
        }
    }

    @Override
    public void save(Status entity) {
        try {
            statusRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving status ", e);
        }
    }

    @Override
    public void update(Status entity) {
        try {
            if (statusRepository.findById(entity.getStatusId()).isPresent()) {
                statusRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating status ", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (statusRepository.findById(id).isPresent()) {
                statusRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting status with id: " + id, e);
        }
    }
}
