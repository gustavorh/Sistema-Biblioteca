package dev.gustavorh.lms_dev_10.controllers.members;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.entities.Member;
import dev.gustavorh.lms_dev_10.entities.Status;
import dev.gustavorh.lms_dev_10.entities.User;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.factories.implementations.DefaultServiceFactory;
import dev.gustavorh.lms_dev_10.factories.implementations.JdbcRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IServiceFactory;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import dev.gustavorh.lms_dev_10.services.interfaces.IUserService;
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

@WebServlet({"/members","/members/*"})
public class MemberServlet extends HttpServlet {
    private IService<Member> memberService;
    private IUserService userService;
    private IService<Status> statusService;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);
            IServiceFactory serviceFactory = new DefaultServiceFactory(repositoryFactory);

            memberService = serviceFactory.createMemberService();
            userService = serviceFactory.createUserService();
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
                    request.setAttribute("members", memberService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/members/members.jsp").forward(request, response);
                    break;
                case "/create":
                    request.setAttribute("member", new Member()); // Empty book for the form
                    request.setAttribute("action", "create");
                    request.setAttribute("users", userService.findAll());
                    request.setAttribute("statuses", statusService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/members/form-member.jsp").forward(request, response);
                    break;
                case "/edit":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    request.setAttribute("member", memberService.findById(Long.valueOf(request.getParameter("id"))).get());
                    request.setAttribute("action", "edit");
                    request.setAttribute("users", userService.findAll());
                    request.setAttribute("statuses", statusService.findAll());
                    request.getRequestDispatcher("/WEB-INF/views/members/form-member.jsp").forward(request, response);
                    break;
                case "/delete":
                    if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                        throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                    }
                    memberService.delete(Long.valueOf(request.getParameter("id")));
                    response.sendRedirect(request.getContextPath() + "/members/all");
            }
        } catch (ServiceException e) {
            throw new ServletException("Error processing member form", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getPathInfo();
        try {
            if (path.equals("/create")) {
                // Populate book object from form parameters
                Member member = buildMember(request, response);

                // Validate the member data
                Map<String, String> errors = validateMember(member);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("member", member);
                    request.setAttribute("users", userService.findAll());
                    request.setAttribute("statuses", statusService.findAll());
                    request.setAttribute("action", "create");
                    request.getRequestDispatcher("/WEB-INF/views/members/form-member.jsp")
                            .forward(request, response);
                    return;
                }
                memberService.save(member);
                // Redirect to member list
                response.sendRedirect(request.getContextPath() + "/members/all");
            } else if (path.equals("/edit")) {
                if (request.getParameter("id") == null || request.getParameter("id").isBlank()) {
                    throw new BadRequestException("El ID no debe ser nulo ni un string vacío.");
                }
                Member member = buildMember(request, response);
                member.setMemberId(Long.valueOf(request.getParameter("id")));

                // Validate the member data
                Map<String, String> errors = validateMember(member);

                if (!errors.isEmpty()) {
                    request.setAttribute("errors", errors);
                    request.setAttribute("member", member);
                    request.setAttribute("users", userService.findAll());
                    request.setAttribute("statuses", statusService.findAll());
                    request.setAttribute("action", "edit");
                    request.getRequestDispatcher("/WEB-INF/views/members/form-member.jsp")
                            .forward(request, response);
                    return;
                }
                memberService.update(member);
                response.sendRedirect(request.getContextPath() + "/members/all");
            }
        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        } catch (ServiceException e) {
            throw new ServletException("Error saving member", e);
        }
    }

    private Map<String, String> validateMember(Member member) {
        Map<String, String> errors = new HashMap<>();

        if (member.getRut() == null || member.getRut().isBlank()) {
            errors.put("rut", "El RUT no puede ser nulo ni un string vacío.");
        }

        if (member.getUser().getUserId() == null) {
            errors.put("userId", "El ID de usuario no puede ser nulo.");
        }

        if (member.getName() == null || member.getName().isBlank()) {
            errors.put("name", "El nombre no puede ser nulo ni un string vacío.");
        }

        if (member.getPaternalSurname() == null || member.getPaternalSurname().isBlank()) {
            errors.put("paternalSurname", "El apellido paterno no puede ser nulo ni un string vacío.");
        }

        if (member.getMaternalSurname() == null || member.getMaternalSurname().isBlank()) {
            errors.put("maternalSurname", "El apellido materno no puede ser nulo ni un string vacío.");
        }

        if (member.getRegistrationDate() == null) {
            errors.put("registrationDate", "La fecha de inscripción no puede ser nula.");
        }

        if (member.getStatus().getStatusId() == null) {
            errors.put("statusId", "El ID de estado no puede ser nulo.");
        }

        return errors;
    }

    private Member buildMember(HttpServletRequest request, HttpServletResponse response) {
        Member member = new Member();
        member.setRut(request.getParameter("rut"));

        User user = new User();
        user.setUserId(Long.valueOf(request.getParameter("userId")));
        user.setUserName(request.getParameter("userName"));
        member.setUser(user);

        member.setName(request.getParameter("name"));
        member.setPaternalSurname(request.getParameter("paternalSurname"));
        member.setMaternalSurname(request.getParameter("maternalSurname"));
        member.setRegistrationDate(LocalDateTime.parse(request.getParameter("registrationDate")));

        Status status = new Status();
        status.setStatusId(Long.valueOf(request.getParameter("statusId")));
        status.setName(request.getParameter("statusName"));
        member.setStatus(status);

        return member;
    }
}
