#pragma once
// #include <windows.h>
#include <list>
// #include<afxwin.h>		//Cstring包含头文件
/*用这个
fatal error C1189 : #error :  afxstr.h can only be used in MFC projects.  Use atlstr.h
*/
// #include <atlstr.h>
using std::list;
#include <map>
using std::map;
#define MYCONTINUE		0x200	
/*
//表示命令功能成功执行而且是（t、p、g等）指示被调试程序继续执行的命令
这样设定是和"u","d"命令区分开,方便它们能不跟数据也能后续输出
*/
#define MYERRCONTINUE	0x300	//表示命令参数输入错误可重新输入的错误
// #define MYMODEINPUT		0x55	//用户输入模式
// #define MYMODESP		0x33	//脚本模式

#define DBGOUT(format,error) \
printf("%s , 第%d行: " ## format ,  __FUNCTION__ ,__LINE__,error)

class COperate
{
public:
	COperate();
	~COperate();
	void DebugMain();
	//普通断点节点
private:
	enum BP_RWE
	{
		ACCESS = 1,	//访问读、写
		WRITE = 2,	//写入
		EXECUTE = 3,	//执行
	};

	//内存、硬件断点节点
	typedef struct{
		DWORD       dwBpOrder;		//断点序号
		//构造函数中初始化为FALSE,成功设置硬件断点后设为TRUE
		BOOL        isActive;       //是否有效
		BOOL		isResume;		//是否需要恢复针对硬件断点
		LPVOID      lpBpAddr;		//断点地址
		BP_RWE		enuBpRWE;		//断点读、写、执行属性
		DWORD       dwBpLen;		//断点长度
		DWORD		dwOldProtect;   //之前的内存页属性
	}BPNODE, *PBPNODE;

	//模块节点结构
	typedef struct{
		DWORD		dwModBase;
		DWORD		dwModSize;
		DWORD		dwModEntry;
		CString		szModName;
		CString		szModPath;
	}DLLNODE, *PDLLNODE;

	//普通断点节点
	typedef struct{
		DWORD       dwBpOrder;		//断点序号
		/*
		是否生效(设置FALSE,就会在单步异常中恢复断点(还需要一个值共同决定))
		只要在触发的int3断点是自己设置的,就设置FALSE,在单步异常中处理后设true
		在刚开始加int3断点时,默认设置TRUE
		*/
		BOOL        isActive;  
		BOOL		isOnce;			//一次性断点
		LPVOID      lpBpAddr;		//断点地址
		char		OldByte;		//保存之前的字节
	}INT3BPNODE, *PINT3BPNODE;

	list<INT3BPNODE>		g_Int3BpList;	//普通断点链表
	list<BPNODE>			g_MemBplist;		//内存断点链表
	map<DWORD, DWORD>		g_MemPagMap;		//内存分页属性表前面为内存分页起始地址，后面为保存的内存分页属性
	DWORD	g_dwBpOrder = 0;				//断点序号从0开始递增
	list<DLLNODE>			DllList;			//模块链表
	map<DWORD, CString>		ApiExportNameMap;		//模块导出函数名称
	// 	static BOOL isSystemBreak;
	//是否是系统断点
	BOOL isSystemBreak = TRUE;
// 	HANDLE hThread;
// 	HANDLE m_pi.hProcess;
// 	CONTEXT context;

	//是否恢复int3断点(只是初步判断,还需要是永久失效断点)
	BOOL isResumeInt3Bp = FALSE;
	BOOL isResumeHardBp = FALSE;
	BOOL isResumeMemBp = FALSE;

	/*
	BPNODE HardBp[4] = { {1,FALSE}, {2,FALSE}, {3,FALSE}, {4,FALSE} };				//4个硬件断点信息
	在类里边这个结构体不能初始化,导致设置硬件断点时失败,放在构造函数中才成功.
	*/
	BPNODE HardBp[4];				//4个硬件断点信息
	DWORD	dwBpOrder = 0;				//断点序号从0开始递增

	//决定是否为用户单步调试,如果是触发int3,或者硬件,内存断点引发的设置FALSE
	//在单步步入,单步步过中认为TRUE
	BOOL isUserStep = FALSE;	
// 	DWORD	dwShowDataAddr = 0;		//数据连续显示地址
	/*g_dwShowDataAddr
	//my-设置该项是因为执行D(后边不跟地址)命令后,需要更新当前地址到最后显示列,
	设置g_dwShowDisasmAddr同样如此
	*/
// 	DWORD	dwShowDisasmAddr = 0;		//反汇编代码连续显示地址

	//////////////////////////////////////////////////////////////////////////
	LPDEBUG_EVENT m_pDbgEvt;
	PROCESS_INFORMATION m_pi;
	LPVOID m_lpBaseOfImage;
	WCHAR *szPath=nullptr;
private:
	//调试信息分发
	DWORD DispatchDbgEvent( DEBUG_EVENT &DebugEvent);
	//创建进程
	DWORD OnCreateProcess(DEBUG_EVENT& DebugEvent);
	//异常分发
	DWORD DispatchException( DEBUG_EVENT &DebugEvent );
	//int3异常
	DWORD OnExceptionInt3Bp( DEBUG_EVENT &DebugEvent );
	//单步异常//硬件异常
	DWORD OnExceptionSingleStep( DEBUG_EVENT &DebugEvent );
	//设置INT3断点
	DWORD CmdSetInt3BP( DWORD dwAddress, BOOL IsAlways=TRUE );
	//设置条件断点
	DWORD CmdSetIfBp ( DWORD dwStartAddress,DWORD dwEndAdderss );
	//显示int3断点
	DWORD CmdShowGeneralBPList();
	//删除int3断点
	DWORD CmdDelGeneralBP( DWORD dwOrder );
	//帮助
	DWORD CmdShowHelp();
	//单步步入
	DWORD CmdStepInto();
	//运行
	DWORD CmdRun();
	//单步步过
	DWORD CmdStepOver( DEBUG_EVENT &DebugEvent);
	//汇编一条指令
	DWORD DisasmOneCode(HANDLE hProcess, LPVOID pCodeAddr, CString *szDisasm);
	//显示汇编指令//8条
	DWORD CmdShowAsmCode( DWORD dwAddr, DEBUG_EVENT &DebugEvent );
	//显示数据
	DWORD CmdShowData( DWORD dwAddr, DEBUG_EVENT &DebugEvent );
	//设置硬件断点
	DWORD CmdSetHardBP( DWORD dwAddr, DWORD dwLen, CHAR *pType );
	//显示硬件断点列表
	DWORD CmdShowHardBPList();
	//删除硬件断点
	DWORD CmdDelHardBP( DWORD dwOrder );
	//设置内存断点
	DWORD CmdSetMemBP( DWORD dwAddr, DWORD dwLen, CHAR *pType );
	//设置在一个分页以内的内存断点
	DWORD SetMemBpOnOnePag(LPVOID lpBpAddr, DWORD dwLen, BP_RWE enuMemBpRwe);
	//显示内存断点
	DWORD CmdShowMemBPList();
	DWORD CmdShowPagMemBPList();
	//删除内存断点
	DWORD CmdDelMemBP( DWORD dwOrder );
	//内存访问异常
	DWORD OnExceptionAccess( DEBUG_EVENT &DebugEvent );
	//显示模块
	DWORD CmdShowMod( DEBUG_EVENT &DebugEvent );
	//得到当前模块
	BOOL GetCurrentModules( DEBUG_EVENT &DebugEvent );
	//显示导出表
	DWORD CmdShowExportTable();
	//显示导入表
	DWORD CmdShowImportTable();
	//显示一条汇编指令
	DWORD ShowDisasmOneCode( LPVOID pCodeAddr);
	//用户输入
	DWORD UserInput( DEBUG_EVENT &DebugEvent );
	//打印寄存器
	void ShowRegInfo ( LPCONTEXT lpContext );
	//显示寄存器
	DWORD CmdShowReg();
	//显示堆栈
	DWORD CmdShowStack ();
	//加载dll
	DWORD OnLoadDll( DEBUG_EVENT &DebugEvent);
	//RVA->offset
	DWORD RVAToOffset ( IMAGE_DOS_HEADER* pDos, DWORD dwRva );
};

