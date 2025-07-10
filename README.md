# renderdoc-everything

![windows ci](https://github.com/gameknife/renderdoc-everything/actions/workflows/windows.yml/badge.svg)

renderdoc-everything 是一个DLL包装器，它允许您在任何（希望是）使用D3D/Vulkan的游戏中使用RenderDoc进行图形调试，包括steam下的游戏。

A dll wrapper tool that enables RenderDoc integration with any( maybe ) D3D/Vulkan game for graphics debugging and analysis, including steam games.



### 主要特性

- 🎮 支持任何使用 D3D/Vulkan 的游戏，项目将持续修复不能成功注入的游戏
- 🚀 无需手动Launch，注入，ChildProcess Hook。通过关键dll自动注入。
- 🔄 自动生成包装器代码，支持各种dll的注入

## 构建步骤

### 前置要求

- Visual Studio 2019 或更高版本
- CMake 3.10 或更高版本
- Python 3.x（用于生成包装器代码）
- Windows SDK

### 编译说明

1. **克隆仓库**
   ```bash
   git clone https://github.com/gameKnife/renderdoc-everything.git
   cd renderdoc-everything
   ```

2. **生成包装器代码**
   ```bash
   python gen_wrapperfile.py dxgi.dll
   ```
    > dxgi.dll是一个好的选择，如果dxgi注入失败，你也可以换成任何其他可以用于注入的dll。执行前请拷贝dll到根目录

3. **编译项目**
   
   使用批处理文件快速编译：
   ```bash
   build.bat
   ```

### 构建输出

编译完成后，您将在root目录下找到：
- `dxgi.dll` - 包装后的DLL
- `dxgi_orig.dll` - 原始DLL（项目repo提供的dxgi.dll是处理过的，请不要将他拷贝到游戏目录）

## 使用方法

1. **部署包装器**
   ```bash
   # 将编译生成的 dxgi.dll 复制到游戏的可执行文件目录
   # 如果是dxgi.dll这种system32目录下有的dll，请不要拷贝_orig.dll，让注入器自己从系统拷贝
   copy dxgi.dll "C:\Path\To\Your\Game"
   # 将你的renderdoc目录下的renderdoc.dll拷贝到游戏的可执行文件目录
   copy renderdoc.dll "C:\Path\To\Your\Game"
   ```

3. **启动游戏**
   - 正常启动游戏
   - 注入器会自动从system32目录拷贝对应dll到_orig.dll并进行注入
   - RenderDoc 功能将自动集成
   - RenderDoc徽标会出现在左上角，可使用F12进行截帧

## 故障排除

### 常见问题

**Q: 游戏启动失败或崩溃**
- 请不要用项目提供的dxgi.dll生成的dxgi_org.dll
- 自行从system32拷贝一份自己操作系统版本的dxgi.dll到项目目录重新构建
- 确保使用的dll能够在同一目录下生成或找到对应的_orig.dll

**Q: 编译错误**
- 检查 Visual Studio 和 Windows SDK 版本
- 确保所有依赖项已正确安装
- 运行 `gen_wrapperfile.py xxx.dll` 重新生成包装器代码
- 通过项目的ci action获得帮助

## 许可证

本项目基于 MIT 许可证开源。详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request！
