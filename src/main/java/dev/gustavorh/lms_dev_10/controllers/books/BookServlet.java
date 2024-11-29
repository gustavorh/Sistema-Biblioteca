package dev.gustavorh.lms_dev_10.controllers.books;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Author;
import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.entities.Category;
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

@WebServlet({"/books","/books/*"})
public class BookServlet extends HttpServlet {
    private IService<Book> bookService;
    private IService<Author> authorService;
    private IService<Category> categoryService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            bookService = serviceFactory.createBookService();
            authorService = serviceFactory.createAuthorService();
            categoryService = serviceFactory.createCategoryService();
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
                    request.setAttribute("books", bookService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/books/books.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("book", new Book()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.setAttribute("authors", authorService.findAll());
                    request.setAttribute("categories", categoryService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/books/form-book.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("book", bookService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.setAttribute("authors", authorService.findAll());
                    request.setAttribute("categories", categoryService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/books/form-book.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    bookService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/books/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing book form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Book book = buildBook(request, response);

                // Validate the book data
                Map<String, String> errors = validateBook(book);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("book", book);
                    request.setAttribute("authors", authorService.findAll());
                    request.setAttribute("categories", categoryService.findAll());
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/books/form-book.jsp")
                            .forward(request, response);
                    return;
                }
                bookService.save(book);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/books/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Book book = buildBook(request, response);
                book.setBookId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validateBook(book);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("book", book);
                    request.setAttribute("authors", authorService.findAll());
                    request.setAttribute("categories", categoryService.findAll());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/books/form-book.jsp")
                            .forward(request, response);
                    return;
                }
                bookService.update(book);
                response.sendRedirect(request.getContextPath() + "/books/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving book", e);
        }
    }

    private Map<String, String> validateBook(Book book) {
        Map<String, String> errors = new HashMap<>();

        if (book.getTitle() == null || book.getTitle().trim().isEmpty()) {
            errors.put("title", "Title is required");
        }

        if (book.getIsbn() == null || book.getIsbn().trim().isEmpty()) {
            errors.put("isbn", "ISBN is required");
        }

        if (book.getPublicationYear() <= 0) {
            errors.put("publicationYear", "Invalid publication year");
        }

        if (book.getAuthor() == null || book.getAuthor().getAuthorId() <= 0) {
            errors.put("authorId", "Author is required");
        }

        if (book.getCategory() == null || book.getCategory().getCategoryId() <= 0) {
            errors.put("categoryId", "Category is required");
        }

        return errors;
    }

    private Book buildBook(HttpServletRequest request, HttpServletResponse response) {
        Book book = new Book();
        book.setTitle(request.getParameter("title"));
        book.setIsbn(request.getParameter("isbn"));
        book.setPublicationYear(Integer.parseInt(request.getParameter("publicationYear")));

        // Set author
        Author author = new Author();
        author.setAuthorId(Long.valueOf(request.getParameter("authorId")));
        book.setAuthor(author);

        // Set category
        Category category = new Category();
        category.setCategoryId(Long.valueOf(request.getParameter("categoryId")));
        book.setCategory(category);

        return book;
    }
}
