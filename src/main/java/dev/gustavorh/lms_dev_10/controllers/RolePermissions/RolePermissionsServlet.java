package dev.gustavorh.lms_dev_10.controllers.RolePermissions;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Permission;
import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.entities.RolePermissions;
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

@WebServlet({"/role_permissions","/role_permissions/*"})
public class RolePermissionsServlet extends HttpServlet {
    private IService<RolePermissions> rolePermissionsService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            rolePermissionsService = serviceFactory.createRolePermissionsService();
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
                    request.setAttribute("rolePermissions", rolePermissionsService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/role_permissions/role_permissions.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("rolePermission", new RolePermissions()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/role_permissions/form-role_permission.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("rolePermission", rolePermissionsService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/role_permissions/form-role_permission.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    rolePermissionsService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/role_permissions/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing RolePermissions form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                RolePermissions rolePermission = buildRolePermissions(request, response);

                // Validate the book data
                Map<String, String> errors = validateRolePermissions(rolePermission);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("rolePermission", rolePermission);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/role_permissions/form-role_permission.jsp")
                            .forward(request, response);
                    return;
                }
                rolePermissionsService.save(rolePermission);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/role_permissions/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                RolePermissions rolePermission = buildRolePermissions(request, response);

                // Validate the book data
                Map<String, String> errors = validateRolePermissions(rolePermission);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("rolePermission", rolePermission);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/role_permissions/form-role_permission.jsp")
                            .forward(request, response);
                    return;
                }
                rolePermissionsService.update(rolePermission);
                response.sendRedirect(request.getContextPath() + "/role_permissions/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving RolePermissions", e);
        }
    }

    private Map<String, String> validateRolePermissions(RolePermissions rolePermissions) {
        Map<String, String> errors = new HashMap<>();


        return errors;
    }

    private RolePermissions buildRolePermissions(HttpServletRequest request, HttpServletResponse response) {
        RolePermissions rolePermissions = new RolePermissions();
        Role role = new Role();
        Permission permission = new Permission();

        role.setRoleId(Long.valueOf(request.getParameter("id_rol")));
        role.setName(request.getParameter("nombre_rol"));
        rolePermissions.setRole(role);
        permission.setPermissionId(Long.valueOf(request.getParameter("id_permiso")));
        permission.setName(request.getParameter("nombre_permiso"));
        rolePermissions.setPermission(permission);

        return rolePermissions;
    }
}
