# 跨域请求的几种解决方案


## 需求背景
最近做的Apigate优化，前端的同学要求能在配置后台页面上加上一键测试接口的功能，但是由于浏览器的[同源策略](https://baike.baidu.com/item/%E5%90%8C%E6%BA%90%E7%AD%96%E7%95%A5/3927875?fr=aladdin)防止[跨域攻击](https://baike.baidu.com/item/CSRF/2735433)，所以前端的页面默认是不能请求其他域名的接口。

## 方案一 Nginx配置代理

	location /proxy {
       if ($arg_url) {
          proxy_pass $arg_url?;
        }
	 }

最开始为了简单就配置了一个简单的代理，通过url传入想要访问的接口例如：

	http://nginxserver/proxy?url=http://10.23.39.140:8080/app/list
	
这样前端需要什么测试什么接口只需要通过url传过来，Nginx会方向代理到对应的url上返回结果。

但是这个方法有个问题，url中的地址支持IP访问，不支持域名的接口访问，在测试环境还可以，线上环境就不支持了，所以Pass了。

## 方案二 JSONP 

> JSONP(JSON with Padding)是JSON的一种“使用模式”，可用于解决主流浏览器的跨域数据访问的问题。由于同源策略，一般来说位于 server1.example.com 的网页无法与不是 server1.example.com的服务器沟通，而 HTML的`<script>`元素是一个例外。利用` <script>` 元素的这个开放策略，网页可以得到从其他来源动态产生的 JSON 资料，而这种使用模式就是所谓的 JSONP。用 JSONP 抓到的资料并不是 JSON，而是任意的JavaScript，用 JavaScript 直译器执行而不是用 JSON 解析器解析。


说白了就是利用	`<script>`的`src`可以跨域的属性，使用接口返回js函数包装的数据

	<script type="text/javascript" src="http://www.yiwuku.com/myService.aspx?jsonp=callbackFunction"></script>
	
假设正常数据返回 { "age" : 15, "name": "John", }
JSONP 就返回一个js包装数据的函数 jsonhandle({ "age" : 15, "name": "John", })

这种方案需要修改现有接口，Apigate的接口都是对外提供的，肯定不能改成这种格式，所以Pass。


## 方案三 Access-Control-Allow-Origin 

#### Nginx配置
只需要在Nginx的配置文件中配置以下参数：

	location / {  
	  add_header Access-Control-Allow-Origin *;
	  add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept";
	  add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
	} 


1. Access-Control-Allow-Origin
服务器默认是不被允许跨域的。给Nginx服务器配置Access-Control-Allow-Origin *后，表示服务器可以接受所有的请求源（Origin）,即接受所有跨域的请求。

2. Access-Control-Allow-Headers 是为了防止出现以下错误：
Request header field Content-Type is not allowed by Access-Control-Allow-Headers in preflight response.这个错误表示当前请求Content-Type的值不被支持。其实是我们发起了"application/json"的类型请求导致的。这里涉及到一个概念：预检请求（preflight request）,请看下面"预检请求"的介绍。

3. Access-Control-Allow-Methods 是为了防止出现以下错误：
Content-Type is not allowed by Access-Control-Allow-Headers in preflight response.
发送"预检请求"时，需要用到方法 OPTIONS ,所以服务器需要允许该方法。

##### 代码中控制

在代码层面，我们可以控制什么接口允许跨域，什么接口不允许跨域，这样对测试层面来说更灵活一些。

	// 在正式跨域的请求前，浏览器会根据需要，发起一个“PreFlight”
	//（也就是Option请求），用来让服务端返回允许的方法（如get、post），
	// 被跨域访问的Origin（来源，或者域），还有是否需要Credentials(认证信息）
	r.OPTIONS("/*allpath", func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.String(http.StatusOK, "ok")
	})


	router.GET("/", func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.String(http.StatusOK, "Hello World")
	})

比如上面我只在测试环境下允许所有的Apigate接口跨域。