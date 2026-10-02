# 申诉证据封存库

SQLite 保存受理记录，本地文件保存证据字节。一次申诉可多次补充证据，
每次成功受理产生一个不可修改的版本。图片、聊天记录、支付引用统一
作为带类型标签的文件处理，不解析内容。

## 文件

- `evidence_seal.py` — 库实现（`SealStore.seal / verify / recover`）
- `crash_child.py` — 测试用子进程助手（被 SIGKILL 强杀以模拟崩溃）
- `test_evidence_seal.py` — 自动化测试

## 使用

```python
from evidence_seal import SealStore, EntryInput

store = SealStore("/path/to/store")      # 目录内含 seal.db 与 evidence/
store.recover()                          # 进程重启后先恢复（幂等）

receipt = store.seal("appeal-1", "req-001", [
    EntryInput("screenshot", "image", "/tmp/a.png"),
    EntryInput("dialog",     "chat",  "/tmp/chat.txt"),
])
# receipt = Receipt(appeal_id, version, root_hash)，调用方独立保存

manifests = store.verify(receipt)        # 校验该版本及全部历史前缀
```

- 同一 `request_id` 重试返回原回执，即使已有更新版本或源文件已删除。
- 版本从 1 开始连续编号；根摘要绑定申诉标识、版本、前一根摘要以及
  本次证据的顺序、逻辑标识、类型与完整字节摘要。
- `verify` 以传入回执为信任锚，逐版本重算哈希链并核对证据字节。
- `recover` 清理未受理提交的暂存与证据文件，可随时中断重跑。

## 运行测试

```sh
python3 -m pytest test_evidence_seal.py -v
```
