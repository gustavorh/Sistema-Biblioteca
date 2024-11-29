package dev.gustavorh.lms_dev_10.controllers.statuses;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Status;
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

@WebServlet({"/statuses","/statuses/*"})
public class StatusServlet extends HttpServlet {
    private IService<Status> statusService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            statusService = serviceFactory.createStatusService();
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
                    request.setAttribute("statuses", statusService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/statuses/statuses.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("status", new Status()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/statuses/form-status.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("status", statusService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/statuses/form-status.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    statusService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/statuses/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing status form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Status status = buildStatus(request, response);

                // Validate the book data
                Map<String, String> errors = validateStatus(status);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("status", status);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/statuses/form-status.jsp")
                            .forward(request, response);
                    return;
                }
                statusService.save(status);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/statuses/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Status status = buildStatus(request, response);
                status.setStatusId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validateStatus(status);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("status", status);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/statuses/form-status.jsp")
                            .forward(request, response);
                    return;
                }
                statusService.update(status);
                response.sendRedirect(request.getContextPath() + "/statuses/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving status", e);
        }
    }

    private Map<String, String> validateStatus(Status status) {
        Map<String, String> errors = new HashMap<>();

        if (status.getName() == null || status.getName().isBlank()) {
            errors.put("name", "El nombre no puede estar vacío.");
        }

        return errors;
    }

    private Status buildStatus(HttpServletRequest request, HttpServletResponse response) {
        Status status = new Status();
        status.setName(request.getParameter("name"));
        status.setDescription(request.getParameter("description"));
        return status;
    }
}
