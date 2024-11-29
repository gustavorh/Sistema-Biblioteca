package dev.gustavorh.lms_dev_10.services.interfaces;

import dev.gustavorh.lms_dev_10.entities.User;

public interface IUserService extends IService<User> {
    User findByUserName(String userName);
    void assignRole(Long userId, Long roleId);
}
