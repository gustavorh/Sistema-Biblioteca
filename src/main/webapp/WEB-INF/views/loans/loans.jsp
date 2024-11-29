<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="/WEB-INF/layouts/header.jsp" />
<%@ taglib uri="jakarta.tags.core" prefix="c"%>
<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Loan Management</h2>
        <a href="${pageContext.request.contextPath}/loans/create" class="btn btn-primary">
            Create New Loan
        </a>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                    <tr>
                        <th>ID</th>
                        <th>Título Libro</th>
                        <th>Nombre Miembro</th>
                        <th>Fecha Desde</th>
                        <th>Fecha Hasta</th>
                        <th>Fecha Devolución</th>
                        <c:if test="${sessionScope.loggedIn}">
                            <th colspan="2">Acciones</th>
                        </c:if>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach items="${loans}" var="l">
                        <tr>
                            <td>${l.loanId}</td>
                            <td>${l.book.title}</td>
                            <td>${l.member.name} ${l.member.paternalSurname} ${l.member.maternalSurname}</td>
                            <td>${l.loanDate}</td>
                            <td>${l.dueDate}</td>
                            <td>${l.returnDate}</td>
                            <c:if test="${sessionScope.loggedIn}">
                                <td>
                                    <div class="btn-group" role="group">
                                        <a href="${pageContext.request.contextPath}/loans/edit?id=${l.loanId}"
                                           class="btn btn-sm btn-warning">Edit</a>
                                        <button type="button" class="btn btn-sm btn-danger"
                                                onclick="confirmDelete(${l.loanId})">Delete</button>
                                    </div>
                                </td>
                            </c:if>
                        </tr>
                    </c:forEach>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
    function confirmDelete(id) {
        if (confirm('Are you sure you want to delete this Book?')) {
            window.location.href = '${pageContext.request.contextPath}/loans/delete?id=' + id;
        }
    }
</script>
<jsp:include page="/WEB-INF/layouts/footer.jsp" />