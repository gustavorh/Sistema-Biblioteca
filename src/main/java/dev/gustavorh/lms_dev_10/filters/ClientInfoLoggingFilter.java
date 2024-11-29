package dev.gustavorh.lms_dev_10.filters;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@WebFilter("/*")
public class ClientInfoLoggingFilter implements Filter {
    private static final String DB_URL = "jdbc:sqlserver://localhost:1433;databaseName=Audits;trustServerCertificate=true";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "^.r}fPr~A/Kj";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException, IOException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (!getClientIpAddress(httpRequest).equalsIgnoreCase("127.0.0.1")) {
            try {
                logToDatabase(httpRequest);
            } catch (SQLException e) {
                // Log the error or handle it appropriately
                e.printStackTrace();
            }
        }

        chain.doFilter(request, response);
    }

    private void logToDatabase(HttpServletRequest request) throws SQLException {
        String sql = "INSERT INTO request_logs " +
                "(timestamp, ip_address, user_agent, request_url, http_method, referrer) " +
                "VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setObject(1, LocalDateTime.now(ZoneOffset.UTC));
            pstmt.setString(2, getClientIpAddress(request));
            pstmt.setString(3, request.getHeader("User-Agent"));
            pstmt.setString(4, request.getRequestURL().toString());
            pstmt.setString(5, request.getMethod());
            pstmt.setString(6, request.getHeader("Referer"));

            pstmt.executeUpdate();
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String[] IP_HEADERS = {
                "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR", "HTTP_X_FORWARDED",
                "HTTP_FORWARDED_FOR", "HTTP_FORWARDED",
                "HTTP_CLIENT_IP", "HTTP_PROXY_CONNECTION"
        };

        for (String header : IP_HEADERS) {
            String ip = request.getHeader(header);
            if (ip != null && ip.length() != 0 && !"unknown".equalsIgnoreCase(ip)) {
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    // Create this table in your database
    // SQL to create the table:
    /*
    CREATE TABLE request_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME NOT NULL,
        ip_address VARCHAR(45),
        user_agent VARCHAR(255),
        request_url VARCHAR(2048),
        http_method VARCHAR(10),
        referrer VARCHAR(2048)
    );
    */
}
