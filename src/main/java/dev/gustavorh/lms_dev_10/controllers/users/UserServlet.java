package dev.gustavorh.lms_dev_10.controllers.users;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.User;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.factories.implementations.DefaultServiceFactory;
import dev.gustavorh.lms_dev_10.factories.implementations.JdbcRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IServiceFactory;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.BadRequestException;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

@WebServlet({"/users","/users/*"})
public class UserServlet extends HttpServlet {
    private IService<User> userService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            userService = serviceFactory.createUserService();
        } catch (SQLException e) {
            throw new ServletException("Error initializing services", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();

        try {
            switch (path) {
                case "/", "/all":
                    request.setAttribute("users", userService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/users/users.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("user", new User()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.setAttribute("users", userService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/users/form-user.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("user", userService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/users/form-user.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    userService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/users/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing user form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                User user = buildUser(request, response);

                // Validate the book data
                Map<String, String> errors = validateUser(user);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("user", user);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/users/form-user.jsp")
                            .forward(request, response);
                    return;
                }
                userService.save(user);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/users/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                User user = buildUser(request, response);
                user.setUserId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validateUser(user);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("user", user);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/users/book-user.jsp")
                            .forward(request, response);
                    return;
                }
                userService.update(user);
                response.sendRedirect(request.getContextPath() + "/users/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving user", e);
        }
    }

    private Map<String, String> validateUser(User user) {
        Map<String, String> errors = new HashMap<>();

        if (user.getUserName() == null || user.getUserName().isBlank()) {
            errors.put("userName", "El nombre de usuario es requerido");
        }

        if (user.getPassword() == null || user.getPassword().isBlank()) {
            errors.put("password", "La contraseña es requerida");
        }

        return errors;
    }

    private User buildUser(HttpServletRequest request, HttpServletResponse response) {
        User user = new User();
        user.setUserName(request.getParameter("userName"));
        user.setPassword(request.getParameter("password"));

        return user;
    }
}
