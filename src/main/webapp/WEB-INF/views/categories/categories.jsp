<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="/WEB-INF/layouts/header.jsp" />
<%@ taglib uri="jakarta.tags.core" prefix="c"%>
<div class="container mt-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Categories Management</h2>
    <a href="${pageContext.request.contextPath}/categories/create" class="btn btn-primary">
      Create New Category
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
            <c:if test="${sessionScope.loggedIn}">
              <th colspan="2">Acciones</th>
            </c:if>
          </tr>
          </thead>
          <tbody>
          <c:forEach items="${categories}" var="c">
            <tr>
              <td>${c.categoryId}</td>
              <td>${c.name}</td>
              <c:if test="${sessionScope.loggedIn}">
                <td>
                  <div class="btn-group" role="group">
                    <a href="${pageContext.request.contextPath}/categories/edit?id=${c.categoryId}"
                       class="btn btn-sm btn-warning">Edit</a>
                    <button type="button" class="btn btn-sm btn-danger"
                            onclick="confirmDelete(${c.categoryId})">Delete</button>
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
      window.location.href = '${pageContext.request.contextPath}/categories/delete?id=' + id;
    }
  }
</script>
<jsp:include page="/WEB-INF/layouts/footer.jsp" />