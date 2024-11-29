<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="/WEB-INF/layouts/header.jsp" />
<%@ taglib uri="jakarta.tags.core" prefix="c"%>
<div class="container mt-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Statuses Management</h2>
    <a href="${pageContext.request.contextPath}/statuses/create" class="btn btn-primary">
      Create New Status
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
            <th>Descripción</th>
            <c:if test="${sessionScope.loggedIn}">
              <th colspan="2">Acciones</th>
            </c:if>
          </tr>
          </thead>
          <tbody>
          <c:forEach items="${statuses}" var="s">
            <tr>
              <td>${s.statusId}</td>
              <td>${s.name}</td>
              <td>${s.description}</td>
              <c:if test="${sessionScope.loggedIn}">
                <td>
                  <div class="btn-group" role="group">
                    <a href="${pageContext.request.contextPath}/statuses/edit?id=${s.statusId}"
                       class="btn btn-sm btn-warning">Edit</a>
                    <button type="button" class="btn btn-sm btn-danger"
                            onclick="confirmDelete(${s.statusId})">Delete</button>
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
      window.location.href = '${pageContext.request.contextPath}/statuses/delete?id=' + id;
    }
  }
</script>
<jsp:include page="/WEB-INF/layouts/footer.jsp" />