<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="/WEB-INF/layouts/header.jsp" />
<%@ taglib uri="jakarta.tags.core" prefix="c"%>
<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Reports Management</h2>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                    <tr>
                        <th>RUT</th>
                        <th>Nombre Completo</th>
                        <th>Estado</th>
                        <th>Fecha Inscripción</th>
                        <th>Total Préstamos</th>
                        <th>Préstamos Atrasados</th>
                        <th>Préstamos Activos</th>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach items="${reportData}" var="member">
                    <tr>
                        <td>${member.rut}</td>
                        <td>${member.fullName}</td>
                        <td>${member.state}</td>
                        <td>${member.registrationDate}</td>
                        <td>${member.totalHistoricalLoans}</td>
                        <td>${member.overdueLoans}</td>
                        <td>${member.activeLoans}</td>
                    </tr>
                    </c:forEach>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<jsp:include page="/WEB-INF/layouts/footer.jsp" />