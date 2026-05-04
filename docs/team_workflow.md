# Team Workflow

## 分支规则

main 分支只保存稳定版本，成员不得直接修改 main。

每个成员开发新功能时，需要创建 feature 分支，例如：

- feature/task-contract
- feature/action-ir
- feature/policy-engine
- feature/bench-cases

## 提交流程

1. 从 main 拉取最新代码
2. 创建自己的 feature 分支
3. 完成一个小功能
4. 写清楚 commit message
5. push 到 GitHub
6. 创建 Pull Request
7. 负责人 review 后合并

## Commit Message 规范

- init: 初始化项目
- docs: 修改文档
- feat: 新增功能
- fix: 修复问题
- test: 添加测试
- chore: 杂项修改

## 禁止事项

- 禁止上传真实密钥
- 禁止上传 .env
- 禁止直接修改 main
- 禁止一次性提交大量无关文件
- 禁止用“最终版”“修改一下”“111”作为提交信息
