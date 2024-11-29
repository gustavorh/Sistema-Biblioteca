package dev.gustavorh.lms_dev_10.controllers.permissions;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Permission;
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

@WebServlet({"/permissions","/permissions/*"})
public class PermissionServlet extends HttpServlet {
    private IService<Permission> permissionService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            permissionService = serviceFactory.createPermissionService();
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
                    request.setAttribute("permissions", permissionService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/permissions/permissions.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("permission", new Permission()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/permissions/form-permission.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("permission", permissionService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/permissions/form-permission.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    permissionService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/permissions/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing permission form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Permission permission = buildPermission(request, response);

                // Validate the book data
                Map<String, String> errors = validatePermission(permission);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("permission", permission);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/permissions/form-permission.jsp")
                            .forward(request, response);
                    return;
                }
                permissionService.save(permission);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/permissions/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Permission permission = buildPermission(request, response);
                permission.setPermissionId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validatePermission(permission);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("permission", permission);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/permissions/form-permission.jsp")
                            .forward(request, response);
                    return;
                }
                permissionService.update(permission);
                response.sendRedirect(request.getContextPath() + "/permissions/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving permission", e);
        }
    }

    private Map<String, String> validatePermission(Permission permission) {
        Map<String, String> errors = new HashMap<>();

        if (permission.getName() == null || permission.getName().isBlank()) {
            errors.put("name", "El nombre no puede estar vacío.");
        }

        if (permission.getDescription() == null || permission.getDescription().isBlank()) {
            errors.put("description", "La descripción no puede estar vacía.");
        }

        return errors;
    }

    private Permission buildPermission(HttpServletRequest request, HttpServletResponse response) {
        Permission permission = new Permission();
        permission.setName(request.getParameter("name"));
        permission.setDescription(request.getParameter("description"));
        return permission;
    }
}
