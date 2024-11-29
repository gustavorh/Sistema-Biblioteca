<!-- WEB-INF/views/books/form.jsp -->
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="/WEB-INF/layouts/header.jsp"/>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">${action == 'edit' ? 'Edit' : 'Create'} Member</h4>
                </div>
                <div class="card-body">
                    <!-- Display global errors if any -->
                    <c:if test="${not empty errorMessage}">
                        <div class="alert alert-danger" role="alert">
                                ${errorMessage}
                        </div>
                    </c:if>

                    <form method="post" action="${pageContext.request.contextPath}/members/${action}" class="needs-validation" novalidate>
                        <c:if test="${action == 'edit'}">
                            <input type="hidden" name="id" value="${member.memberId}">
                        </c:if>

                        <div class="mb-3">
                            <label for="rut" class="form-label">RUT</label>
                            <input type="text"
                                   class="form-control ${not empty errors.rut ? 'is-invalid' : ''}"
                                   id="rut"
                                   name="rut"
                                   value="${member.rut}"
                                   required>
                            <c:if test="${not empty errors.rut}">
                                <div class="invalid-feedback">
                                        ${errors.rut}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="userId" class="form-label">Usuario</label>
                            <select class="form-select ${not empty errors.userId ? 'is-invalid' : ''}"
                                    id="userId"
                                    name="userId"
                                    required>
                                <option value="">Selecciona un usuario</option>
                                <c:forEach items="${users}" var="user">
                                    <option value="${user.userId}"
                                        ${member.user.userId == user.userId ? 'selected' : ''}>
                                            ${user.userName}
                                    </option>
                                </c:forEach>
                            </select>
                            <c:if test="${not empty errors.statusId}">
                                <div class="invalid-feedback">
                                        ${errors.statusId}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="name" class="form-label">Nombre</label>
                            <input type="text"
                                   class="form-control ${not empty errors.name ? 'is-invalid' : ''}"
                                   id="name"
                                   name="name"
                                   value="${member.name}"
                                   required>
                            <c:if test="${not empty errors.name}">
                                <div class="invalid-feedback">
                                        ${errors.name}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="paternalSurname" class="form-label">Apellido Paterno</label>
                            <input type="text"
                                   class="form-control ${not empty errors.paternalSurname ? 'is-invalid' : ''}"
                                   id="paternalSurname"
                                   name="paternalSurname"
                                   value="${member.paternalSurname}"
                                   required>
                            <c:if test="${not empty errors.paternalSurname}">
                                <div class="invalid-feedback">
                                        ${errors.paternalSurname}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="maternalSurname" class="form-label">Apellido Materno</label>
                            <input type="text"
                                   class="form-control ${not empty errors.maternalSurname ? 'is-invalid' : ''}"
                                   id="maternalSurname"
                                   name="maternalSurname"
                                   value="${member.maternalSurname}"
                                   required>
                            <c:if test="${not empty errors.maternalSurname}">
                                <div class="invalid-feedback">
                                        ${errors.maternalSurname}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="registrationDate" class="form-label">Fecha Inscripción</label>
                            <input type="datetime-local"
                                   class="form-control ${not empty errors.registrationDate ? 'is-invalid' : ''}"
                                   id="registrationDate"
                                   name="registrationDate"
                                   value="${member.registrationDate}"
                                   required>
                            <c:if test="${not empty errors.registrationDate}">
                                <div class="invalid-feedback">
                                        ${errors.registrationDate}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="statusId" class="form-label">Estado</label>
                            <select class="form-select ${not empty errors.statusId ? 'is-invalid' : ''}"
                                    id="statusId"
                                    name="statusId"
                                    required>
                                <option value="">Selecciona un estado</option>
                                <c:forEach items="${statuses}" var="status">
                                    <option value="${status.statusId}"
                                        ${member.status.statusId == status.statusId ? 'selected' : ''}>
                                            ${status.name}
                                    </option>
                                </c:forEach>
                            </select>
                            <c:if test="${not empty errors.statusId}">
                                <div class="invalid-feedback">
                                        ${errors.statusId}
                                </div>
                            </c:if>
                        </div>

                        <div class="d-flex justify-content-end gap-2">
                            <a href="${pageContext.request.contextPath}/members/all"
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