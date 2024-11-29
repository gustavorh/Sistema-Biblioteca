package dev.gustavorh.lms_dev_10.controllers.loans;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.entities.Loan;
import dev.gustavorh.lms_dev_10.entities.Member;
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
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@WebServlet({"/loans","/loans/*"})
public class LoanServlet extends HttpServlet {
    private IService<Loan> loanService;
    private IService<Member> memberService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            loanService = serviceFactory.createLoanService();
            memberService = serviceFactory.createMemberService();
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
                    request.setAttribute("loans", loanService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/loans/loans.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("loan", new Loan()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.setAttribute("members", memberService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/loans/form-loan.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("loan", loanService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.setAttribute("members", memberService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/loans/form-loan.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    loanService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/loans/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing loan form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Loan loan = buildLoan(request, response);

                // Validate the book data
                Map<String, String> errors = validateRole(loan);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("loan", loan);
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/loans/form-loan.jsp")
                            .forward(request, response);
                    return;
                }
                loanService.save(loan);
                // Redirect to book list
                response.sendRedirect(request.getContextPath() + "/loans/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Loan loan = buildLoan(request, response);
                loan.setLoanId(Long.valueOf(request.getParameter("id")));

                // Validate the book data
                Map<String, String> errors = validateRole(loan);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("loan", loan);
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/loans/form-loan.jsp")
                            .forward(request, response);
                    return;
                }
                loanService.update(loan);
                response.sendRedirect(request.getContextPath() + "/loans/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving loan", e);
        }
    }

    private Map<String, String> validateRole(Loan loan) {
        Map<String, String> errors = new HashMap<>();

        if (loan.getBook().getBookId() == null) {
            errors.put("book", "El libro no puede ser nulo.");
        }

        if (loan.getMember().getMemberId() == null) {
            errors.put("user", "El usuario no puede ser nulo.");
        }

        if (loan.getLoanDate() == null) {
            errors.put("loanDate", "La fecha de préstamo no puede ser nula.");
        }

        if (loan.getReturnDate() == null) {
            errors.put("returnDate", "La fecha de devolución no puede ser nula.");
        }

        if (loan.getDueDate() == null) {
            errors.put("returnDate", "La fecha de devolución no puede ser nula.");
        }

        return errors;
    }

    private Loan buildLoan(HttpServletRequest request, HttpServletResponse response) {
        Loan loan = new Loan();
        Book book = new Book();
        Member member = new Member();

        book.setBookId(Long.valueOf(request.getParameter("bookId")));
        book.setTitle(request.getParameter("title"));
        loan.setBook(book);
        member.setMemberId(Long.valueOf(request.getParameter("memberId")));
        member.setName(request.getParameter("name"));
        member.setPaternalSurname(request.getParameter("paternalSurname"));
        member.setMaternalSurname(request.getParameter("maternalSurname"));
        loan.setMember(member);
        loan.setLoanDate(LocalDateTime.parse(request.getParameter("loanDate")));
        loan.setDueDate(LocalDateTime.parse(request.getParameter("dueDate")));
        loan.setReturnDate(LocalDateTime.parse(request.getParameter("returnDate")));

        return loan;
    }
}
