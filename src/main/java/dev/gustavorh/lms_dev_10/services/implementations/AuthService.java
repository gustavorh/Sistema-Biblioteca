package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.User;
import dev.gustavorh.lms_dev_10.services.interfaces.IAuthService;
import dev.gustavorh.lms_dev_10.services.interfaces.IUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.Optional;

public class AuthService implements IAuthService {
    private final IUserService userService;

    public AuthService(IUserService userService) {
        this.userService = userService;
    }

    @Override
    public Boolean isLoggedIn(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Boolean loggedIn = (Boolean) session.getAttribute("loggedIn");

        return loggedIn != null && loggedIn;
    }

    @Override
    public Optional<User> login(String userName, String password){
        return Optional.ofNullable(userService.findByUserName(userName))
                .filter(user -> user.getPassword().equals(password)); // Returns user matching password.
    }

    @Override
    public Optional<String> getUsername(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Boolean loggedIn = (Boolean) session.getAttribute("loggedIn");

        if (loggedIn != null && loggedIn) {
            return Optional.of((String) session.getAttribute("username"));
        }

        return Optional.empty();
    }
}
