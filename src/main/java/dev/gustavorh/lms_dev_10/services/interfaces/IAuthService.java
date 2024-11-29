package dev.gustavorh.lms_dev_10.services.interfaces;

import dev.gustavorh.lms_dev_10.entities.User;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface IAuthService {
    Boolean isLoggedIn(HttpServletRequest request);
    Optional<String> getUsername(HttpServletRequest request);
    Optional<User> login(String userName, String password);
}
