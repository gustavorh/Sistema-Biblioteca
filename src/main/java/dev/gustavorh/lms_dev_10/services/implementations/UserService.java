package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.User;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IUserRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IUserService;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class UserService implements IUserService {
    private final IUserRepository userRepository;

    public UserService(IUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<User> findById(Long id) {
        try {
            return userRepository.findById(id);
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving user with id: " + id, e);
        }
    }

    @Override
    public List<User> findAll() {
        try {
            return userRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all users", e);
        }
    }

    @Override
    public void save(User entity) {
        try {
            userRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving user", e);
        }
    }

    @Override
    public void update(User entity) {
        try {
            userRepository.update(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error updating user", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            userRepository.delete(id);
        } catch (SQLException e) {
            throw new ServiceException("Error deleting user with id: " + id, e);
        }
    }

    @Override
    public User findByUserName(String userName) {
        try {
            return userRepository.findByUserName(userName);
        } catch (SQLException e) {
            throw new ServiceException("Error deleting user with username: " + userName, e);
        }
    }

    @Override
    public void assignRole(Long userId, Long roleId) {
        try {
            userRepository.updateRole(userId, roleId);
        } catch (SQLException e) {
            throw new ServiceException("Error assigning role to user with id: " + userId, e);
        }
    }
}
