# SUKI IDA
SUKI IDA is a continuously updated IDA plugin collection.  
IDA is the most powerful reverse analysis tool, she has a powerful decompilation engine, so i like she so much. Let's make it stronger !   
SUKI IDA 是一个持续更新的IDA插件集合。  
IDA 是最强大的逆向分析工具，她拥有强大的反编译引擎，所以我非常喜欢她。所以让我们把她变得更强大！

# Set up
Put SUKI_IDA folder and SUKI_IDA_PLUGIN.py file into IDA plugin folder.  

# Tool list 
## Dynamic Variables Check
 
Dynamic identification of variable values when debug running.   
When you debug shellcode, there are many function to be created, and might be some API Waiting to be identified.  
DVA can help you easily finish it.  
  
调试的时候动态检查局部变量的值。  
当你调试shellcode的时候，这里会有许多待创建的函数，或许还会有一些等待识别的系统API。  
DVA可以帮助你轻松的完成这些任务。  

Detail: https://github.com/miunasu/DynamicVarCheck_IDA

## RE-AI
Use idapython create call topology, AI analysis function layer by layer. Get the target function conclusion.  

利用idapython创建函数调用拓扑，AI逐层分析函数，最终总结目标函数的功能。  

Detail: https://github.com/miunasu/REAI_IDA

## Export Function Check
EFC is simple tool, that will help you distinguish between malicious functions and fake export function.  
EFC 是一个能帮助你区分恶意函数和伪造导出函数的小工具。  
[README_EFC](./DOC/README_EFC.md)

# Support
The plugin suport 7.4 between 9.x.  
If you have any question or idea, please open an issue on GitHub.  


