<!-- WEB-INF/views/books/form.jsp -->
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="/WEB-INF/layouts/header.jsp"/>

<div class="container mt-4">
  <div class="row justify-content-center">
    <div class="col-md-8">
      <div class="card">
        <div class="card-header">
          <h4 class="mb-0">${action == 'edit' ? 'Edit' : 'Create'} Role</h4>
        </div>
        <div class="card-body">
          <!-- Display global errors if any -->
          <c:if test="${not empty errorMessage}">
            <div class="alert alert-danger" role="alert">
                ${errorMessage}
            </div>
          </c:if>

          <form method="post" action="${pageContext.request.contextPath}/roles/${action}" class="needs-validation" novalidate>
            <c:if test="${action == 'edit'}">
              <input type="hidden" name="id" value="${role.roleId}">
            </c:if>

            <div class="mb-3">
              <label for="name" class="form-label">Nombre</label>
              <input type="text"
                     class="form-control ${not empty errors.name ? 'is-invalid' : ''}"
                     id="name"
                     name="name"
                     value="${role.name}"
                     required>
              <c:if test="${not empty errors.name}">
                <div class="invalid-feedback">
                    ${errors.name}
                </div>
              </c:if>
            </div>

            <div class="mb-3">
              <label for="description" class="form-label">Descripción</label>
              <input type="text"
                     class="form-control ${not empty errors.description ? 'is-invalid' : ''}"
                     id="description"
                     name="description"
                     value="${role.description}"
                     required>
              <c:if test="${not empty errors.description}">
              <div class="invalid-feedback">
                  ${errors.description}
              </div>
              </c:if>

              <div class="d-flex justify-content-end gap-2">
                <a href="${pageContext.request.contextPath}/roles/all"
                   class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary">Save</button>
              </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Custom validation script -->
<script>
  // Enable Bootstrap form validation
  (function () {
    'use strict'
    var forms = document.querySelectorAll('.needs-validation')
    Array.prototype.slice.call(forms)
            .forEach(function (form) {
              form.addEventListener('submit', function (event) {
                if (!form.checkValidity()) {
                  event.preventDefault()
                  event.stopPropagation()
                }
                form.classList.add('was-validated')
              }, false)
            })
  })()
</script>

<jsp:include page="/WEB-INF/layouts/footer.jsp"/>