package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.RoleUsers;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class RoleUsersService implements IService<RoleUsers> {
    private final IRepository<RoleUsers> roleUsersRepository;

    public RoleUsersService(IRepository<RoleUsers> roleUsersRepository) {
        this.roleUsersRepository = roleUsersRepository;
    }

    @Override
    public Optional<RoleUsers> findById(Long id) {
        try {
            Optional<RoleUsers> roleUsersOptional = roleUsersRepository.findById(id);
            if (roleUsersOptional.isPresent()) {
                return roleUsersOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving RoleUser with id: " + id, e);
        }
    }

    @Override
    public List<RoleUsers> findAll() {
        try {
            return roleUsersRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all RoleUsers", e);
        }
    }

    @Override
    public void save(RoleUsers entity) {
        try {
            roleUsersRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving RoleUser", e);
        }
    }

    @Override
    public void update(RoleUsers entity) {
        try {
            if (roleUsersRepository.findById(entity.getRole().getRoleId()).isPresent()) {
                roleUsersRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating RoleUser", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (roleUsersRepository.findById(id).isPresent()) {
                roleUsersRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting RoleUser with id: " + id, e);
        }
    }
}
