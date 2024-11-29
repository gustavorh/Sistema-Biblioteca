<!-- WEB-INF/views/books/form.jsp -->
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="/WEB-INF/layouts/header.jsp"/>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4 class="mb-0">${action == 'edit' ? 'Edit' : 'Create'} Book</h4>
                </div>
                <div class="card-body">
                    <!-- Display global errors if any -->
                    <c:if test="${not empty errorMessage}">
                        <div class="alert alert-danger" role="alert">
                                ${errorMessage}
                        </div>
                    </c:if>

                    <form method="post" action="${pageContext.request.contextPath}/books/${action}" class="needs-validation" novalidate>
                        <c:if test="${action == 'edit'}">
                            <input type="hidden" name="id" value="${book.bookId}">
                        </c:if>

                        <div class="mb-3">
                            <label for="title" class="form-label">Title</label>
                            <input type="text"
                                   class="form-control ${not empty errors.title ? 'is-invalid' : ''}"
                                   id="title"
                                   name="title"
                                   value="${book.title}"
                                   required>
                            <c:if test="${not empty errors.title}">
                                <div class="invalid-feedback">
                                        ${errors.title}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="isbn" class="form-label">ISBN</label>
                            <input type="text"
                                   class="form-control ${not empty errors.isbn ? 'is-invalid' : ''}"
                                   id="isbn"
                                   name="isbn"
                                   value="${book.isbn}"
                                   required>
                            <c:if test="${not empty errors.isbn}">
                                <div class="invalid-feedback">
                                        ${errors.isbn}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="publicationYear" class="form-label">Publication Year</label>
                            <input type="number"
                                   class="form-control ${not empty errors.publicationYear ? 'is-invalid' : ''}"
                                   id="publicationYear"
                                   name="publicationYear"
                                   value="${book.publicationYear}"
                                   min="1800"
                                   max="2024"
                                   required>
                            <c:if test="${not empty errors.publicationYear}">
                                <div class="invalid-feedback">
                                        ${errors.publicationYear}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="authorId" class="form-label">Author</label>
                            <select class="form-select ${not empty errors.authorId ? 'is-invalid' : ''}"
                                    id="authorId"
                                    name="authorId"
                                    required>
                                <option value="">Select an author</option>
                                <c:forEach items="${authors}" var="author">
                                    <option value="${author.authorId}"
                                        ${book.author.authorId == author.authorId ? 'selected' : ''}>
                                            ${author.fullName}
                                    </option>
                                </c:forEach>
                            </select>
                            <c:if test="${not empty errors.authorId}">
                                <div class="invalid-feedback">
                                        ${errors.authorId}
                                </div>
                            </c:if>
                        </div>

                        <div class="mb-3">
                            <label for="categoryId" class="form-label">Category</label>
                            <select class="form-select ${not empty errors.categoryId ? 'is-invalid' : ''}"
                                    id="categoryId"
                                    name="categoryId"
                                    required>
                                <option value="">Select a category</option>
                                <c:forEach items="${categories}" var="category">
                                    <option value="${category.categoryId}"
                                        ${book.category.categoryId == category.categoryId ? 'selected' : ''}>
                                            ${category.name}
                                    </option>
                                </c:forEach>
                            </select>
                            <c:if test="${not empty errors.categoryId}">
                                <div class="invalid-feedback">
                                        ${errors.categoryId}
                                </div>
                            </c:if>
                        </div>

                        <div class="d-flex justify-content-end gap-2">
                            <a href="${pageContext.request.contextPath}/books/all"
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