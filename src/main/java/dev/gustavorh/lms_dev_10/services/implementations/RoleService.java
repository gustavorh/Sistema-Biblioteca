package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class RoleService implements IService<Role> {
    private final IRepository<Role> roleRepository;

    public RoleService(IRepository<Role> roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public Optional<Role> findById(Long id) {
        try {
            Optional<Role> memberOptional = roleRepository.findById(id);
            if (memberOptional.isPresent()) {
                return memberOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving role with id: " + id, e);
        }
    }

    @Override
    public List<Role> findAll() {
        try {
            return roleRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all roles", e);
        }
    }

    @Override
    public void save(Role entity) {
        try {
            roleRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving role", e);
        }
    }

    @Override
    public void update(Role entity) {
        try {
            if (roleRepository.findById(entity.getRoleId()).isPresent()) {
                roleRepository.update(entity);
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
            if (roleRepository.findById(id).isPresent()) {
                roleRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting role with id: " + id, e);
        }
    }
}
