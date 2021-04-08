


## 环境配置

### Docker File 编写
	
	#源镜像
	FROM golang:latest
	# 容器环境变量添加，会覆盖默认的变量值
	ENV GOPROXY=https://goproxy.cn,direct
	ENV GO111MODULE="on"
	ENV test="on"

	# 作者
	LABEL author="fanlv"
	LABEL email="fanlvlgh@gmail.com"
	#设置工作目录
	WORKDIR /go/src/gitee.com/fanlv/GolangDemo/GoTest/docker
	# 复制仓库源文件到容器里
	COPY . .
	
	# 编译可执行二进制文件(一定要写这些编译参数，指定了可执行程序的运行平台,参考：https://www.jianshu.com/p/4b345a9e768e)
	RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mem_test -gcflags "-N -l" gotest.go
	
	# 构建生产镜像，使用最小的linux镜像，只有5M
	# 同一个文件里允许多个FROM出现的，每个FROM被称为一个阶段，多个FROM就是多个阶段，最终以最后一个FROM有效，以前的FROM被抛弃
	# 多个阶段的使用场景就是将编译环境和生产环境分开
	# 参考：https://docs.docker.com/engine/reference/builder/#from
	FROM alpine:latest
	WORKDIR /root/
	# 从编译阶段复制文件
	# 这里使用了阶段索引值，第一个阶段从0开始，如果使用阶段别名则需要写成 COPY --from=build_stage /go/src/app/webserver /
	COPY --from=0 /go/src/gitee.com/fanlv/GolangDemo/GoTest/docker .
	#暴露端口
	EXPOSE 8000
	#最终运行docker的命令
	ENTRYPOINT  ["./mem_test"]

### Docker File 发布

	# 编译 docker file
	# docker build -t gomemtest .
	# 运行
	# docker run --name gomemtest -p 8000:8000 -d  gomemtest
	#发布docker
	# docker tag gomemtest fanlv/gomemtest
	# docker push fanlv/gomemtest
	
	# docker tag gomemtest fanlv/gomemtest:v1.0.0
	# docker push fanlv/gomemtest:tagname:v1.0.0


### 进入容器

	docker exec -it gomemtest sh 




### 安装 minikube

[minikube Installation](https://minikube.sigs.k8s.io/docs/start/)



	brew install minikube
	
	brew install kubernetes-cli
	
	kubectl get po -A  
	
	minikube kubectl -- get po -A


### 部署 Application

	kubectl create deployment mem --image=fanlv/gomemtest
	
	kubectl delete -n default deployment mem 
	
	kubectl get services mem

	minikube service mem  // web 访问服务端口
	
	kubectl port-forward service/mem 8000:8000



### LoadBalancer deployments 

	kubectl create deployment balanced --image=k8s.gcr.io/echoserver:1.4  
	kubectl expose deployment balanced --type=LoadBalancer --port=8080
	
	
	minikube tunnel
	kubectl get services balanced


### node

	k get nodes // 获取node
	k describe node minikube // 输出显示了节点的状态、 CPU 和内存数据、系统信息、运行容器的节点等



### Pods

	k get pods
	k get services


###

k run mem --image=fanlv/gomemtest --port=8000 --generator=run/v1

k expose rc mem --type=LoadBalancer --name mem-http





### kubectl explain 来发现可能的 API 对象字段

	kubectl explain pods
	
	kubectl explain pod.spec
	
	
### 使用 kubectl create 来创建 pod

	 kubectl create -f kubia-manual.yaml
	 
	 
### 得到运行中 pod 的完整定义

	 kubectl get po kubia-manual -o yaml
	 
	 kubectl get po kubia-manual -o json
	 
	 
### pod 列表中查看新创建的 pod

	kubectl get pods

### 查看应用程序日志

	docker logs <container id>
	
	kubectl get <pod name>

	kubectl get <pod name> -c <容器 名称>


### 将本地网络端口转发到pod中的端口

	kubectl port-forward kubia manual 8888:8080

### 使用标签组织pod
![image.png](https://upload-images.jianshu.io/upload_images/12321605-10bd1c785d3dc87d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

	kubectl create -f kubia-manual-with-labels.yaml
	
	kubectl get po --show-labels
		
	k label po balanced-5b47687d6d-n2svl evn=debug --overwrite
	
	
### 使用标签选择器列出 pod

	kubectl get po -l creation_method=manual
	
	kubectl get po -l env
	
	
	
### 查找对象的注解

	kubectl get po kubia-zxzij -o yaml
	
	// 添加和修改注解
	kubectl annotate pod kubia-manual mycompany . com/someannotation="foo bar ”
	
	kubectl describe pod kubia-manual
	
	


### 停止和移除pod

	kubectl delete po kubia-gpu
	
	// 使用标签选择器删除 pod
	kubectl delete po -1 creation method=manual
	
	//
	kubectl delete po - 1 rel=canary
	
	// 删除命名空间中的（几乎）所有资源
	kubec tl delete all --all
	
	// 查看之前的日志
	k logs balanced-5b47687d6d-n2svl --previous
	
	
![image.png](https://upload-images.jianshu.io/upload_images/12321605-10bd1c785d3dc87d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

	kubectl create -f kubia-rc.yaml

### 水平缩放 pod

	kubectl scale re kubia --replicas=lO
	
	
1. 单体应用，方便部署。 不好水平扩展。
2. 微服务，扩容方便，只用针对单个服务扩容。
3. 微服务调试变得困难，依赖各个模块。 还需要做服务治理。
4. 环境差异。 依赖库版本不同。

docker 好处。 
1. 提供一致的开发环境。简单了部署流程，服务发布流程化。
2. 比虚拟机更轻量。

k8s好处
1. 简化应用部署。
2. 更好利用硬件。
3. 健康检查和自修复。
4. 自动扩容