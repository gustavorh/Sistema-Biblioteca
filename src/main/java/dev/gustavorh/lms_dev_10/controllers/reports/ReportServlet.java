package dev.gustavorh.lms_dev_10.controllers.reports;

import dev.gustavorh.lms_dev_10.config.DbContext;
import dev.gustavorh.lms_dev_10.dtos.MemberActivityReportDTO;
import dev.gustavorh.lms_dev_10.factories.implementations.JdbcRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IRepositoryFactory;
import dev.gustavorh.lms_dev_10.repositories.implementations.MemberActivityReportRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

@WebServlet("/reports/*")
public class ReportServlet extends HttpServlet {
    private MemberActivityReportRepository reportRepository;

    @Override
    public void init() throws ServletException {
        try {
            Connection connection = DbContext.getConnection();
            IRepositoryFactory repositoryFactory = new JdbcRepositoryFactory(connection);

            reportRepository = repositoryFactory.createMemberActivityReportRepository();
        } catch (SQLException e) {
            throw new ServletException("Error initializing services", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String reportType = request.getPathInfo();
        String destination = "";

        switch (reportType) {
            case "/activity":
                List<MemberActivityReportDTO> activityReport;
                try {
                    activityReport = reportRepository.getActivityReport();
                } catch (SQLException e) {
                    throw new RuntimeException(e.getCause());
                }
                request.setAttribute("reportData", activityReport);
                request.setAttribute("reportTitle", "Member Activity Report");
                destination = "/WEB-INF/views/reports/activity-report.jsp";
                break;
            // Add other report cases here
            default:
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
        }

        request.getRequestDispatcher(destination).forward(request, response);
    }
}
