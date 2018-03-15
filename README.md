### 使用说明

- 生成参数。参数文件位于当前目录下PARAMS目录中。
该操作只需要最开始执行一次即可。
```
cargo run --release --bin gen_params
```
- 单项测试。
```
cargo run --release --bin tree_test
cargo run --release --bin bench
```
- 转账流程集成测试。
```
cargo run --release --bin round_test
cargo run --release --bin contract_test
```
- 跟CITA的系统测试。首先要运行CITA。
```
cargo run --release --bin client
```