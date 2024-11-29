<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="/WEB-INF/layouts/header.jsp" />
<%@ taglib uri="jakarta.tags.core" prefix="c"%>
<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>RoleUsers Management</h2>
        <a href="${pageContext.request.contextPath}/role_users/create" class="btn btn-primary">
            Create New RoleUser
        </a>
    </div>

    <div class="card">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                    <tr>
                        <th>Nombre</th>
                        <th>Usuario</th>
                        <c:if test="${sessionScope.loggedIn}">
                            <th colspan="2">Acciones</th>
                        </c:if>
                    </tr>
                    </thead>
                    <tbody>
                    <c:forEach items="${roleUsers}" var="ru">
                        <tr>
                            <td>${ru.role.name}</td>
                            <td>${ru.user.userName}</td>
                            <c:if test="${sessionScope.loggedIn}">
                                <td>
                                    <div class="btn-group" role="group">
                                        <a href="${pageContext.request.contextPath}/role_users/edit?id=${ru.role.roleId}"
                                           class="btn btn-sm btn-warning">Edit</a>
                                        <button type="button" class="btn btn-sm btn-danger"
                                                onclick="confirmDelete(${ru.role.roleId})">Delete</button>
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
            window.location.href = '${pageContext.request.contextPath}/role_users/delete?id=' + id;
        }
    }
</script>
<jsp:include page="/WEB-INF/layouts/footer.jsp" />