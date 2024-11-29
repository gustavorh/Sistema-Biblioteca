package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Permission;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class PermissionService implements IService<Permission> {
    private final IRepository<Permission> permissionRepository;

    public PermissionService(IRepository<Permission> permissionRepository) {
        this.permissionRepository = permissionRepository;
    }

    @Override
    public Optional<Permission> findById(Long id) {
        try {
            Optional<Permission> permissionOptional = permissionRepository.findById(id);
            if (permissionOptional.isPresent()) {
                return permissionOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving permission with id: " + id, e);
        }
    }

    @Override
    public List<Permission> findAll() {
        try {
            return permissionRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all permissions", e);
        }
    }

    @Override
    public void save(Permission entity) {
        try {
            permissionRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving permission", e);
        }
    }

    @Override
    public void update(Permission entity) {
        try {
            if (permissionRepository.findById(entity.getPermissionId()).isPresent()) {
                permissionRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating permission", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (permissionRepository.findById(id).isPresent()) {
                permissionRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting permission with id: " + id, e);
        }
    }
}
