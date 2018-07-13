# iOS之GRPC调用服务器（附代码）

## 背景
最近在用gRPC框架测试，想起去年调研Protocol Buffer在HTTP的时候传输，了解过这个框架，当时没深入。这次做gRPC服务器端，随便看下iOS这边如果可以调用。下面做了个简单的Demo，附上代码。

## proto文件 
	
	package user;
	
	message LoginRequest {
	  string username = 1;
	  string password = 2;
	}
	
	message BaseResponse{
	  int64 code = 1;
	  string msg = 2;
	}
	
	message User{
	    string uid = 1;
	    string name = 2;
	    string logo = 3;
	}
	message LoginResponse {
	    User user = 1;
	    BaseResponse baseResp = 255;
	}
	
	//service 名称，客户端会用这个去调用对应方法
	service Greeter {
	    //提供的RPC方法
	  rpc Login (LoginRequest) returns (LoginResponse) {}
	}
	
#### 生成go代码
	--objc_out=plugins=grpc:. user.proto

#### 生成oc代码
	protoc --objc_out=. --grpc_out=. --plugin=protoc-gen-grpc=/usr/local/bin/grpc_objective_c_plugin user.proto


## 服务器代码实现（Go）	
	
	package main
	
	import (
		pb "gitee.com/xxxx/proto"//执行你生成的user.pb.go位置
		"golang.org/x/net/context"
		"net"
		"google.golang.org/grpc"
		"google.golang.org/grpc/reflection"
	
		"log"
	)
	
	const (
		port = ":50051"
	)
	
	
	
	type server struct{}
	
	func (s *server) Login(ctx context.Context, in *pb.LoginRequest) (*pb.LoginResponse, error) {
		var resp *pb.LoginResponse
		if in.Username =="test" && in.Password == "123456" {
			resp = &pb.LoginResponse{
				User:&pb.User{
					Uid:"001",
					Name:"test",
					Logo:"https://test.com/test.png",
				},
				BaseResp:&pb.BaseResponse{
					Code:0,
					Msg:"ok",
				},
			}
		}else {
			resp = &pb.LoginResponse{
				User:nil,
				BaseResp:&pb.BaseResponse{
					Code:1,
					Msg:"login fail",
				},
			}
		}
		return resp,nil
	}
	
	func main() {
		lis, err := net.Listen("tcp", port)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		s := grpc.NewServer()
		pb.RegisterGreeterServer(s, &server{})
		// Register reflection service on gRPC server.
		reflection.Register(s)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	
	}

## 客户端端代码（iOS）	

可以先去官网下一个Demo项目，地址：[grpc.io - objective-c](https://grpc.io/docs/tutorials/basic/objective-c.html#try-it-out)

里面有三个demo，我这里借用的hellowrlod的demo路径`grpc/examples/objective-c/helloworld`。

执行pod install，主要会用到下面几个库

	Installing !ProtoCompiler (3.5.0)
	Installing !ProtoCompiler-gRPCPlugin (1.13.0)
	Installing BoringSSL (10.0.5)
	Installing Protobuf (3.6.0)
	Installing gRPC (1.13.0)
	Installing gRPC-Core (1.13.0)
	Installing gRPC-ProtoRPC (1.13.0)
	Installing gRPC-RxLibrary (1.13.0)
	Installing nanopb (0.3.8)

把生成的四个pb文件（`User.pbobjc.h`、`User.pbobjc.m`、`User.pbrpc.h`、`User.pbrpc.m`）添加到项目中去。然后在main.m中添加下面的测试代码

      Greeter *userClient = [[Greeter alloc] initWithHost:kHostAddress];
      LoginRequest *req = [[LoginRequest alloc] init];
      req.username = @"test";
      req.password = @"123456";

      [userClient loginWithRequest:req handler:^(LoginResponse * _Nullable response, NSError * _Nullable error) {
          if (!error) {
              if (response.baseResp.code == 0) {
                  NSLog(@"%@",response.user.name);
              }else{
                  NSLog(@"error :%@",response.baseResp.msg);
              }
          }else{
              NSLog(@"%@",error);
          }
      }];

调用上面方法可以看到能够正常返回数据。Over