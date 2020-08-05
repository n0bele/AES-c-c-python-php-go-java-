<?php
include("mycrypt.php");
$cryptObj = new MyCrypt();
?>
<html lang="zh-cn">
<head>
<meta charset="utf-8">
<title>在线加密 | 解密 - 在线工具</title>
<style> 
.divcss5-right{width:720px; height:1000px;border:1px solid #F00;float:right} 
</style> 
</head> 
<body>
<form action="index.php" method="post">
<div class="layui-col-md5"> 
<textarea cols="95" rows="20" name="contents"></textarea>
<input type="submit" name="encrypt" value="加密" style="vertical-align:left">
&nbsp;&nbsp;&nbsp;<input type="submit" name="decrypt" value="解密" style="vertical-align:right">
</div>
</form>
<div class="divcss5-right"><?php
if(!isset($_POST['contents']))
	return;
if(!empty($_POST['encrypt']))
{
	echo $cryptObj->encrypt($_POST['contents']);
}else if(!empty($_POST['decrypt']))
{
	echo $cryptObj->decrypt($_POST['contents']);
}
?></div> 
</body></html>