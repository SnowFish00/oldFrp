FROM golang:1.20 as builder

# 设置 Go module 和代理
ENV GOPROXY=https://goproxy.cn,direct
ENV GO111MODULE=on

# 设置工作目录
WORKDIR /root/

# 将代码复制到容器中
COPY . .

# 构建应用程序 若为windows则每一个build都需要加 参数
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Projects/sfc.exe ./cmd/frpc && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Projects/sfs.exe ./cmd/frps && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Tools/sfs_EncryptionTool.exe ./pkg/config/cfgED/Tool/sfs_EncryptAndDecryptTool/sfs_EncryptionTool.go && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Tools/sfs_DecryptionTool.exe ./pkg/config/cfgED/Tool/sfs_EncryptAndDecryptTool/sfs_DecryptionTool.go && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Tools/config_Simplification.exe ./pkg/config/cfgED/Tool/sfc_SimplificationTool/config_Simplification.go && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Tools/config_UnSimplification.exe ./pkg/config/cfgED/Tool/sfc_SimplificationTool/config_UnSimplification.go && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Tools/sfc_EncryptionTool.exe ./pkg/config/cfgED/Tool/sfc_EncryptAndDecryptTool/sfc_EncryptionTool.go && \
CGO_ENABLED=0 GOARCH=amd64 GOOS=windows \
    go build -o bin/Tools/sfc_DecryptionTool.exe ./pkg/config/cfgED/Tool/sfc_EncryptAndDecryptTool/sfc_DecryptionTool.go

FROM alpine

# 设置工作目录
WORKDIR /data/

# 从builder阶段复制二进制文件到当前镜像
COPY --from=builder /root/ .

# 暴露端口
EXPOSE 8080
#创建挂载后移动的目录
CMD ["mkdir -p /app/bin/"]

# 显式指定容器启动时要执行的命令
ENTRYPOINT [ "/bin/sh","-c","mv /data/bin/* /app/bin/ && sleep 1h" ]

#编译 docker build -t sfcs/windows:1.0 .
#挂载 docker run --name=sfcswindows -itd -p 7070:8080 -v F:\sundry\frptest\pure\windows:/app/bin sfcs/windows:1.0