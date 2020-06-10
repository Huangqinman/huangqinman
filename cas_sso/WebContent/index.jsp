<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>主页</title>
</head>
<body>
<h1>欢迎登录。。。</h1>  
<%out.println(session.getAttribute("username")); %></br>
<%out.println(request.getRemoteUser()); %></br>
<%out.println(request.getAttribute("username")); %></br>
</body>
</html>