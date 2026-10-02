# task26100298
# task26100298-a
# 申诉证据封存库（sealstore）

SQLite 保存受理记录，本地文件保存证据字节。图片、聊天记录、支付引用统一作为
带类型标签的文件处理，不解析内容。一次申诉可多次补充证据，每次成功受理产生
一个不可修改、连续编号的版本（从 1 开始）。

## 存储布局

```
<base_dir>/
  seal.db                            # 受理记录：versions / entries / requests
  evidence/<sha256(appeal_id)>/<version>/<seq>   # 封存证据字节
```

## 使用

```python
from sealstore import SealStore, Entry, Receipt

store = SealStore("/path/to/store")

# 封存一组有序证据（可多次补充，版本连续递增）
receipt = store.seal("appeal-123", "req-abc", [
    Entry(logical_id="photo-1", etype="image", source_path="/tmp/a.jpg"),
    Entry(logical_id="chat-1",  etype="chatlog", source_path="/tmp/c.txt"),
])
# receipt: appeal_id / version / root_digest，调用方独立保存（可 to_dict）

# 以传入回执为信任锚，验证该版本及全部历史前缀；返回各版本证据清单
manifests = store.verify(Receipt.from_dict(saved_dict))

# 进程崩溃后重启：清理未受理提交留下的文件；可反复运行直至收敛
store.recover()
```

## 保证

- Seal 先把证据字节写入最终位置（tmp + fsync + rename + 目录 fsync），再用
  单个 SQLite 事务落受理记录：一次提交只整体受理或整体不受理。
- 根摘要绑定 appeal_id、版本、前一版本根摘要及本次证据的顺序、逻辑标识、
  类型与完整字节摘要；Verify 重算整条链并与传入回执比对。
- request_id 库内唯一；已受理请求重试返回原回执（即使已有新版本或源文件
  已删除）。Recover 不依赖源文件，发现已受理证据缺失/损坏会显式报错，
  绝不删除记录或重算摘要掩盖。

## 测试

```
python3 -m unittest discover -s tests -v
```

测试用真实子进程 + SIGKILL 覆盖三个崩溃窗口（部分写入 / 证据落盘未受理 /
已受理未返回回执）以及恢复过程本身被终止后再次收敛的场景。
