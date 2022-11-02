# CodeLLDB Setting

### Quick Start

```
//launch.json configure
{
    "type": "lldb",
    "request": "launch",
    "name": "Debug",
    "program": "${fileDirname}\\${fileBasenameNoExtension}.exe",//Windows
    "args": [],
    "cwd": "${workspaceFolder}"
}
```
### Other setting
1. Keyboard Input:  `ctrl` + `shift` + `p`
2. Search:          `@ext:vadimcn.vscode-lldb`
3. Find Option:
```
Lldb › Launch: Expressions
The default evaluator type used for expressions.
```
4. revise `simple` To `native`

### Debug dynamic arrays
```
//watch sentence
*(ptr_type(*)[size])ptr_name
ptr,num
```
