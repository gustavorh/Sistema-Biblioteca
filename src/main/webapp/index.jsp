<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<jsp:include page="WEB-INF/layouts/header.jsp" />
<div class="container mt-5">
    <div class="jumbotron text-center">
        <h1 class="display-4">Bienvenido al Sistema de Gestión de Biblioteca</h1>
        <p class="lead">Administre de manera eficiente los recursos y operaciones de su biblioteca</p>
        <hr class="my-4">
        <p>Acceda a nuestras herramientas integrales de gestión de biblioteca para manejar libros, socios, préstamos y más.</p>
        <a class="btn btn-primary btn-lg" href="${pageContext.request.contextPath}/books/all" role="button">Explorar Libros</a>
    </div>

    <div class="row mt-5">
        <div class="col-md-4">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Gestión de Libros</h5>
                    <p class="card-text">Administre la colección de libros de su biblioteca de manera eficiente.</p>
                    <a href="${pageContext.request.contextPath}/books/all" class="btn btn-primary">Administrar Libros</a>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Gestión de Socios</h5>
                    <p class="card-text">Administre registros e inscripciones de socios.</p>
                    <a href="${pageContext.request.contextPath}/members/all" class="btn btn-primary">Administrar Socios</a>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">Gestión de Préstamos</h5>
                    <p class="card-text">Realice seguimiento de préstamos y devoluciones de libros.</p>
                    <a href="${pageContext.request.contextPath}/loans/all" class="btn btn-primary">Administrar Préstamos</a>
                </div>
            </div>
        </div>
    </div>
</div>
<jsp:include page="WEB-INF/layouts/footer.jsp" />