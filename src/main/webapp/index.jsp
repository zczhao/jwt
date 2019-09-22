<%@ page language="java" contentType="text/html;charset=utf-8" pageEncoding="utf-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>JWT测试</title>
<script type="text/javascript" src="js/jquery-3.4.1.min.js"></script>
<script type="text/javascript">
 function login(){
	 var username = $("#username").val();
	 var password = $("#password").val();
	 var params = "username=" + username + "&password=" + password;
	 $.ajax({
		 "url" : "${pageContext.request.contextPath}/login",
		 "data" : params,
		 "success" : function(data) {
			 if(data.code == 200) {
				 var token = data.token;
				 // web storage的查看 - 在浏览器的开发者面板中的Application中查看
				 // local storage - 本地存储的数据。长期有效的
				 // session storage - 会话存储的数据。一次会话有效
				 var loalStorage = window.localStorage;
				 localStorage.token = token;
			 }
			 alert(data.msg);
		 }
	 });
 }
 
 function setHeader(xhr) {
	 xhr.setRequestHeader("Authorization",window.localStorage.token);
 }
 
 function testLocalStorage(){
	 $.ajax({
		 "url" : "${pageContext.request.contextPath}/testAll",
		 "beforeSend" : setHeader,
		 "success" : function(data) {
			 if(data.code == 200) {
				 window.localStorage.token = data.token;
				 alert(data.data);
			 } else {
			 	alert(data.msg);
			 }
		 }
	 });
 }
</script>
<body>
	<center>
		<table>
			<caption>登录测试</caption>
			<tr>
				<td style="text-align:right;padding-right:5px">用户名：</td>
				<td style="text-align:left;padding-left:5px">
					<input type="text" name="username" id="username">
				</td>
			</tr>
			<tr>
				<td style="text-align:right;padding-right:5px">密码：</td>
				<td style="text-align:left;padding-left:5px">
					<input type="text" name="password" id="password">
				</td>
			</tr>
			<tr>
				<td style="text-align:right;padding-right:5px" colspan="2">
					<input type="button" value="登录" onclick="login();">
				</td>
			</tr>
		</table>
	</center>
	<input type="button" value="testLocalStorage" onclick="testLocalStorage();">
</body>
</html>