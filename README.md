# 构建
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 运行服务端
./build/bin/tx_server -c config/server.json.example

# 运行客户端
./build/bin/tx_client -c config/client.json.example