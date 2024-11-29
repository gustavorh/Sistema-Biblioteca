<!-- WEB-INF/views/books/form.jsp -->
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="/WEB-INF/layouts/header.jsp"/>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">${action == 'edit' ? 'Edit' : 'Create'} User</h4>
                </div>
                <div class="card-body">
                    <!-- Display global errors if any -->
                    <c:if test="${not empty errorMessage}">
                        <div class="alert alert-danger" role="alert">
                                ${errorMessage}
                        </div>
                    </c:if>

                    <form method="post" action="${pageContext.request.contextPath}/users/${action}" class="needs-validation" novalidate>
                        <c:if test="${action == 'edit'}">
                            <input type="hidden" name="id" value="${user.userId}">
                        </c:if>

                        <div class="mb-3">
                            <label for="userName" class="form-label">Usuario</label>
                            <input type="text"
                                   class="form-control ${not empty errors.userName ? 'is-invalid' : ''}"
                                   id="userName"
                                   name="userName"
                                   value="${user.userName}"
                                   required>
                            <c:if test="${not empty errors.userName}">
                                <div class="invalid-feedback">
                                        ${errors.userName}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="password" class="form-label">Contraseña</label>
                            <input type="password"
                                   class="form-control ${not empty errors.password ? 'is-invalid' : ''}"
                                   id="password"
                                   name="password"
                                   value="${user.password}"
                                   required>
                            <c:if test="${not empty errors.password}">
                            <div class="invalid-feedback">
                                    ${errors.password}
                            </div>
                            </c:if>

                            <div class="d-flex justify-content-end gap-2">
                                <a href="${pageContext.request.contextPath}/users/all"
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