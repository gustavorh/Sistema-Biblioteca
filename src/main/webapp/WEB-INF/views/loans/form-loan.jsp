<%--
  Created by IntelliJ IDEA.
  User: Gustavo
  Date: 19/11/2024
  Time: 11:36 pm
  To change this template use File | Settings | File Templates.
--%>
<!-- WEB-INF/views/books/form.jsp -->
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="/WEB-INF/layouts/header.jsp"/>

<div class="container mt-4">
  <div class="row justify-content-center">
    <div class="col-md-8">
      <div class="card">
        <div class="card-header">
          <h4 class="mb-0">${action == 'edit' ? 'Edit' : 'Create'} Loan</h4>
        </div>
        <div class="card-body">
          <!-- Display global errors if any -->
          <c:if test="${not empty errorMessage}">
            <div class="alert alert-danger" role="alert">
                ${errorMessage}
            </div>
          </c:if>

          <form method="post" action="${pageContext.request.contextPath}/loans/${action}" class="needs-validation" novalidate>
            <c:if test="${action == 'edit'}">
              <input type="hidden" name="id" value="${loan.loanId}">
            </c:if>

            <div class="mb-3">
              <label for="title" class="form-label">Titulo Libro</label>
              <input type="text"
                     class="form-control ${not empty errors.title ? 'is-invalid' : ''}"
                     id="title"
                     name="title"
                     value="${loan.book.title}"
                     required>
              <c:if test="${not empty errors.title}">
                <div class="invalid-feedback">
                    ${errors.title}
                </div>
              </c:if>
            </div>

            <div class="mb-3">
              <label for="memberId" class="form-label">Member</label>
              <select class="form-select ${not empty errors.memberId ? 'is-invalid' : ''}"
                      id="memberId"
                      name="memberId"
                      required>
                <option value="">Select a member</option>
                <c:forEach items="${members}" var="member">
                  <option value="${member.memberId}"
                    ${loan.member.memberId == member.memberId ? 'selected' : ''}>
                      ${member.name} ${member.paternalSurname} ${member.maternalSurname}
                  </option>
                </c:forEach>
              </select>
              <c:if test="${not empty errors.memberId}">
                <div class="invalid-feedback">
                    ${errors.memberId}
                </div>
              </c:if>
            </div>

            <div class="mb-3">
              <label for="loanDate" class="form-label">Fecha Préstamo</label>
              <input type="datetime-local"
                     class="form-control ${not empty errors.loanDate ? 'is-invalid' : ''}"
                     id="loanDate"
                     name="loanDate"
                     value="${loan.loanDate}"
                     required>
              <c:if test="${not empty errors.loanDate}">
                <div class="invalid-feedback">
                    ${errors.loanDate}
                </div>
              </c:if>
            </div>

            <div class="mb-3">
              <label for="dueDate" class="form-label">Fecha Devolución</label>
              <input type="datetime-local"
                     class="form-control ${not empty errors.dueDate ? 'is-invalid' : ''}"
                     id="dueDate"
                     name="dueDate"
                     value="${loan.dueDate}"
                     required>
              <c:if test="${not empty errors.dueDate}">
                <div class="invalid-feedback">
                    ${errors.dueDate}
                </div>
              </c:if>
            </div>

            <div class="mb-3">
              <label for="returnDate" class="form-label">Fecha Entrega</label>
              <input type="datetime-local"
                     class="form-control ${not empty errors.returnDate ? 'is-invalid' : ''}"
                     id="returnDate"
                     name="returnDate"
                     value="${loan.returnDate}"
                     required>
              <c:if test="${not empty errors.returnDate}">
                <div class="invalid-feedback">
                    ${errors.returnDate}
                </div>
              </c:if>
            </div>

            <div class="d-flex justify-content-end gap-2">
              <a href="${pageContext.request.contextPath}/loans/all"
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
