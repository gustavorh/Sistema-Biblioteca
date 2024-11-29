package dev.gustavorh.lms_dev_10.controllers.roles;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Role;
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

@WebServlet({"/roles","/roles/*"})
public class RoleServlet extends HttpServlet {
    private IService<Role> roleService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            roleService = serviceFactory.createRoleService();
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
                    request.setAttribute("roles", roleService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/roles/roles.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("role", new Role()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/roles/form-role.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("role", roleService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/roles/form-role.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    roleService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/roles/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing role form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Role role = buildRole(request, response);

                // Validate the book data
                Map<String, String> errors = validateRole(role);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("role", role);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/roles/form-role.jsp")
                            .forward(request, response);
                    return;
                }
                roleService.save(role);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/roles/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Role role = buildRole(request, response);
                role.setRoleId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validateRole(role);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("role", role);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/roles/form-role.jsp")
                            .forward(request, response);
                    return;
                }
                roleService.update(role);
                response.sendRedirect(request.getContextPath() + "/roles/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving user", e);
        }
    }

    private Map<String, String> validateRole(Role role) {
        Map<String, String> errors = new HashMap<>();

        if (role.getName() == null || role.getName().isBlank()) {
            errors.put("name", "El nombre no puede ser nulo o vacío.");
        }

        if (role.getDescription() == null || role.getDescription().isBlank()) {
            errors.put("description", "La descripción no puede ser nula o vacía.");
        }

        return errors;
    }

    private Role buildRole(HttpServletRequest request, HttpServletResponse response) {
        Role role = new Role();
        role.setName(request.getParameter("name"));
        role.setDescription(request.getParameter("description"));

        return role;
    }
}
