<!-- WEB-INF/views/books/form.jsp -->
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="/WEB-INF/layouts/header.jsp"/>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">${action == 'edit' ? 'Edit' : 'Create'} Author</h4>
                </div>
                <div class="card-body">
                    <!-- Display global errors if any -->
                    <c:if test="${not empty errorMessage}">
                        <div class="alert alert-danger" role="alert">
                                ${errorMessage}
                        </div>
                    </c:if>

                    <form method="post" action="${pageContext.request.contextPath}/authors/${action}" class="needs-validation" novalidate>
                        <c:if test="${action == 'edit'}">
                            <input type="hidden" name="id" value="${author.authorId}">
                        </c:if>

                        <div class="mb-3">
                            <label for="name" class="form-label">Nombre</label>
                            <input type="text"
                                   class="form-control ${not empty errors.name ? 'is-invalid' : ''}"
                                   id="name"
                                   name="name"
                                   value="${author.name}"
                                   required>
                            <c:if test="${not empty errors.name}">
                                <div class="invalid-feedback">
                                        ${errors.name}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="surname" class="form-label">Apellido</label>
                            <input type="text"
                                   class="form-control ${not empty errors.surname ? 'is-invalid' : ''}"
                                   id="surname"
                                   name="surname"
                                   value="${author.surname}"
                                   required>
                            <c:if test="${not empty errors.surname}">
                                <div class="invalid-feedback">
                                        ${errors.surname}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="fullName" class="form-label">Nombre Completo</label>
                            <input type="text"
                                   class="form-control ${not empty errors.fullName ? 'is-invalid' : ''}"
                                   id="fullName"
                                   name="fullName"
                                   value="${author.fullName}"
                                   required>
                            <c:if test="${not empty errors.fullName}">
                                <div class="invalid-feedback">
                                        ${errors.fullName}
                                </div>
                            </c:if>
                        </div>

                        <div class="d-flex justify-content-end gap-2">
                            <a href="${pageContext.request.contextPath}/authors/all"
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