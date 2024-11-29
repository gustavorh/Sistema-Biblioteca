package dev.gustavorh.lms_dev_10.controllers.RoleUsers;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.entities.RoleUsers;
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

@WebServlet({"/role_users","/role_users/*"})
public class RoleUsersServlet extends HttpServlet {
    private IService<RoleUsers> roleUsersService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            roleUsersService = serviceFactory.createRoleUsersService();
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
                    request.setAttribute("roleUsers", roleUsersService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/role_users/role_users.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("roleUser", new RoleUsers()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/role_users/form-role_user.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("roleUser", roleUsersService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/role_users/form-role_user.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    roleUsersService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/role_users/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing RoleUsers form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                RoleUsers roleUser = buildRoleUsers(request, response);

                // Validate the book data
                Map<String, String> errors = validateRoleUsers(roleUser);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("roleUser", roleUser);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/role_users/form-role_user.jsp")
                            .forward(request, response);
                    return;
                }
                roleUsersService.save(roleUser);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/role_users/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                RoleUsers roleUser = buildRoleUsers(request, response);

                // Validate the book data
                Map<String, String> errors = validateRoleUsers(roleUser);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("roleUser", roleUser);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/role_users/form-role_user.jsp")
                            .forward(request, response);
                    return;
                }
                roleUsersService.update(roleUser);
                response.sendRedirect(request.getContextPath() + "/role_users/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving RoleUser", e);
        }
    }

    private Map<String, String> validateRoleUsers(RoleUsers roleUsers) {
        Map<String, String> errors = new HashMap<>();


        return errors;
    }

    private RoleUsers buildRoleUsers(HttpServletRequest request, HttpServletResponse response) {
        RoleUsers roleUser = new RoleUsers();
        Role role = new Role();
        User user = new User();

        role.setRoleId(Long.valueOf(request.getParameter("roleId")));
        role.setName(request.getParameter("name"));
        user.setUserId(Long.valueOf(request.getParameter("userId")));
        user.setUserName(request.getParameter("userName"));
        roleUser.setRole(role);
        roleUser.setUser(user);

        return roleUser;
    }
}
