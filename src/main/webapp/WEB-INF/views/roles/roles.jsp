<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="/WEB-INF/layouts/header.jsp" />
<%@ taglib uri="jakarta.tags.core" prefix="c"%>
<div class="container mt-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Roles Management</h2>
    <a href="${pageContext.request.contextPath}/roles/create" class="btn btn-primary">
      Create New Role
    </a>
  </div>

  <div class="card">
    <div class="card-body">
      <div class="table-responsive">
        <table class="table table-striped">
          <thead>
          <tr>
            <th>ID</th>
            <th>Nombre</th>
            <th>Descripcion</th>
            <c:if test="${sessionScope.loggedIn}">
              <th colspan="2">Acciones</th>
            </c:if>
          </tr>
          </thead>
          <tbody>
          <c:forEach items="${roles}" var="r">
            <tr>
              <td>${r.roleId}</td>
              <td>${r.name}</td>
              <td>${r.description}</td>
              <c:if test="${sessionScope.loggedIn}">
                <td>
                  <div class="btn-group" role="group">
                    <a href="${pageContext.request.contextPath}/roles/edit?id=${r.roleId}"
                       class="btn btn-sm btn-warning">Edit</a>
                    <button type="button" class="btn btn-sm btn-danger"
                            onclick="confirmDelete(${r.roleId})">Delete</button>
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
      window.location.href = '${pageContext.request.contextPath}/roles/delete?id=' + id;
    }
  }
</script>
<jsp:include page="/WEB-INF/layouts/footer.jsp" />