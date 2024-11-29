package dev.gustavorh.lms_dev_10.controllers.auth;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.User;
import dev.gustavorh.lms_dev_10.factories.implementations.DefaultServiceFactory;
import dev.gustavorh.lms_dev_10.factories.implementations.JdbcRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IServiceFactory;
import dev.gustavorh.lms_dev_10.services.interfaces.IAuthService;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;

@WebServlet("/auth/*")
public class AuthServlet extends HttpServlet {
    private IAuthService authService;

    @Override
    public void init(ServletConfig config) throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            authService = serviceFactory.createAuthService();
        } catch (SQLException e) {
            throw new ServletException("Error initializing services", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();

        if (path == null || path.equals("/")) {
            // Base path "/auth" - redirect to index
            req.getRequestDispatcher("/index.jsp").forward(req, resp);
            return;
        }

        switch (path) {
            case "/login":
                // Check if user is already logged in
                Boolean loggedIn = authService.isLoggedIn(req);

                if (loggedIn != null && loggedIn) {
                    req.getRequestDispatcher("/index.jsp").forward(req, resp);
                } else {
                    req.getRequestDispatcher("/WEB-INF/views/auth/login.jsp").forward(req, resp);
                }
                break;

            case "/logout":
                // Invalidate session
                req.getSession().invalidate();
                resp.sendRedirect(req.getContextPath() + "/index.jsp");
                break;

            default:
                resp.sendError(HttpServletResponse.SC_NOT_FOUND);
                break;
        }
    }

    // Se encarga de procesar el login del usuario.
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();

        if ("/login".equals(path)) {
            if (!authService.isLoggedIn(req)) {
                String username = req.getParameter("username");
                String password = req.getParameter("password");

                Optional<User> userOptional = authService.login(username, password);

                if (userOptional.isPresent()) {
                    HttpSession session = req.getSession();
                    session.setAttribute("loggedIn", true);
                    session.setAttribute("username", username);
                    resp.sendRedirect(req.getContextPath() + "/");
                } else {
                    req.setAttribute("title", "Login incorrecto!");
                    resp.sendRedirect(req.getContextPath() + "/auth/login");
                }
            } else {
                req.getRequestDispatcher("/index.jsp").forward(req, resp);
            }
        } else {
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }
}
