<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>E-Lib</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="${pageContext.request.contextPath}/">E-Lib</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav me-auto">
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
            Mantenedores
          </a>
          <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="${pageContext.request.contextPath}/books/all">Libros</a></li>
            <li><a class="dropdown-item" href="${pageContext.request.contextPath}/members/all">Miembros</a></li>
            <li><a class="dropdown-item" href="${pageContext.request.contextPath}/users/all">Usuarios</a></li>
            <li><a class="dropdown-item" href="${pageContext.request.contextPath}/roles/all">Roles</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/loans/all">Préstamos</a></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/categories/all">Categorías</a></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/authors/all">Autores</a></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/statuses/all">Estados</a></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/permissions/all">Permisos</a></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/role_permissions/all">RolPermisos</a></li>
            <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/role_users/all">RolUsuarios</a></li>
          </ul>
        </li>
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
            Reportes
          </a>
          <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="${pageContext.request.contextPath}/reports/activity">Actividad de Miembros</a></li>
          </ul>
        </li>
      </ul>
      <ul class="navbar-nav">
        <c:choose>
          <c:when test="${sessionScope.username != null}">
            <li class="nav-item dropdown">
              <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                  ${sessionScope.username}
              </a>
              <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/profile">Perfil</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item" href="${pageContext.request.contextPath}/auth/logout">Logout</a></li>
              </ul>
            </li>
          </c:when>
          <c:otherwise>
            <li class="nav-item dropdown">
              <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                Account
              </a>
              <ul class="dropdown-menu dropdown-menu-end">
                <li><a class="dropdown-item" href="${pageContext.request.contextPath}/auth/login">Login</a></li>
                <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/auth/register">Registrarse</a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item disabled" href="${pageContext.request.contextPath}/auth/guest">Continuar como Invitado</a></li>
              </ul>
            </li>
          </c:otherwise>
        </c:choose>
      </ul>
    </div>
  </div>
</nav>