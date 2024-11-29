package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.RolePermissions;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class RolePermissionsService implements IService<RolePermissions> {
    private final IRepository<RolePermissions> rolePermissionsRepository;

    public RolePermissionsService(IRepository<RolePermissions> rolePermissionsRepository) {
        this.rolePermissionsRepository = rolePermissionsRepository;
    }

    @Override
    public Optional<RolePermissions> findById(Long id) {
        try {
            Optional<RolePermissions> rolePermissionsOptional = rolePermissionsRepository.findById(id);
            if (rolePermissionsOptional.isPresent()) {
                return rolePermissionsOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving role with id: " + id, e);
        }
    }

    @Override
    public List<RolePermissions> findAll() {
        try {
            return rolePermissionsRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all roles", e);
        }
    }

    @Override
    public void save(RolePermissions entity) {
        try {
            rolePermissionsRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving role", e);
        }
    }

    @Override
    public void update(RolePermissions entity) {
        try {
            if (rolePermissionsRepository.findById(entity.getRole().getRoleId()).isPresent()) {
                rolePermissionsRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating role", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (rolePermissionsRepository.findById(id).isPresent()) {
                rolePermissionsRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting role with id: " + id, e);
        }
    }
}
