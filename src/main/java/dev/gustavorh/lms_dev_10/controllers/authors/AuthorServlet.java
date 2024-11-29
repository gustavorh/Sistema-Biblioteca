package dev.gustavorh.lms_dev_10.controllers.authors;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Author;
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

@WebServlet({"/authors","/authors/*"})
public class AuthorServlet extends HttpServlet {
    private IService<Author> authorService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            authorService = serviceFactory.createAuthorService();
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
                    request.setAttribute("authors", authorService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/authors/authors.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("author", new Author()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/authors/form-author.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("author", authorService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/authors/form-author.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    authorService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/authors/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing author form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Author author = buildAuthor(request, response);

                // Validate the book data
                Map<String, String> errors = validateAuthor(author);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("author", author);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/authors/form-author.jsp")
                            .forward(request, response);
                    return;
                }
                authorService.save(author);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/authors/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Author author = buildAuthor(request, response);
                author.setAuthorId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validateAuthor(author);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("author", author);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/authors/form-author.jsp")
                            .forward(request, response);
                    return;
                }
                authorService.update(author);
                response.sendRedirect(request.getContextPath() + "/authors/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving author", e);
        }
    }

    private Map<String, String> validateAuthor(Author author) {
        Map<String, String> errors = new HashMap<>();

        if (author.getName() == null || author.getName().isBlank()) {
            errors.put("name", "El nombre no puede estar vacío.");
        }

        if (author.getSurname() == null || author.getSurname().isBlank()) {
            errors.put("surname", "El apellido no puede estar vacío.");
        }

        if (author.getFullName() == null || author.getFullName().isBlank()) {
            errors.put("fullName", "El nombre completo no puede estar vacío.");
        }

        return errors;
    }

    private Author buildAuthor(HttpServletRequest request, HttpServletResponse response) {
        Author author = new Author();
        author.setName(request.getParameter("name"));
        author.setSurname(request.getParameter("surname"));
        author.setFullName(request.getParameter("fullName"));
        return author;
    }
}
