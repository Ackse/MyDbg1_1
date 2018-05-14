#pragma once
// #include <windows.h>
#include <list>
// #include<afxwin.h>		//Cstring����ͷ�ļ�
/*�����
fatal error C1189 : #error :  afxstr.h can only be used in MFC projects.  Use atlstr.h
*/
// #include <atlstr.h>
using std::list;
#include <map>
using std::map;
#define MYCONTINUE		0x200	
/*
//��ʾ����ܳɹ�ִ�ж����ǣ�t��p��g�ȣ�ָʾ�����Գ������ִ�е�����
�����趨�Ǻ�"u","d"�������ֿ�,���������ܲ�������Ҳ�ܺ������
*/
#define MYERRCONTINUE	0x300	//��ʾ�����������������������Ĵ���
// #define MYMODEINPUT		0x55	//�û�����ģʽ
// #define MYMODESP		0x33	//�ű�ģʽ

#define DBGOUT(format,error) \
printf("%s , ��%d��: " ## format ,  __FUNCTION__ ,__LINE__,error)

class COperate
{
public:
	COperate();
	~COperate();
	void DebugMain();
	//��ͨ�ϵ�ڵ�
private:
	enum BP_RWE
	{
		ACCESS = 1,	//���ʶ���д
		WRITE = 2,	//д��
		EXECUTE = 3,	//ִ��
	};

	//�ڴ桢Ӳ���ϵ�ڵ�
	typedef struct{
		DWORD       dwBpOrder;		//�ϵ����
		//���캯���г�ʼ��ΪFALSE,�ɹ�����Ӳ���ϵ����ΪTRUE
		BOOL        isActive;       //�Ƿ���Ч
		BOOL		isResume;		//�Ƿ���Ҫ�ָ����Ӳ���ϵ�
		LPVOID      lpBpAddr;		//�ϵ��ַ
		BP_RWE		enuBpRWE;		//�ϵ����д��ִ������
		DWORD       dwBpLen;		//�ϵ㳤��
		DWORD		dwOldProtect;   //֮ǰ���ڴ�ҳ����
	}BPNODE, *PBPNODE;

	//ģ��ڵ�ṹ
	typedef struct{
		DWORD		dwModBase;
		DWORD		dwModSize;
		DWORD		dwModEntry;
		CString		szModName;
		CString		szModPath;
	}DLLNODE, *PDLLNODE;

	//��ͨ�ϵ�ڵ�
	typedef struct{
		DWORD       dwBpOrder;		//�ϵ����
		/*
		�Ƿ���Ч(����FALSE,�ͻ��ڵ����쳣�лָ��ϵ�(����Ҫһ��ֵ��ͬ����))
		ֻҪ�ڴ�����int3�ϵ����Լ����õ�,������FALSE,�ڵ����쳣�д������true
		�ڸտ�ʼ��int3�ϵ�ʱ,Ĭ������TRUE
		*/
		BOOL        isActive;  
		BOOL		isOnce;			//һ���Զϵ�
		LPVOID      lpBpAddr;		//�ϵ��ַ
		char		OldByte;		//����֮ǰ���ֽ�
	}INT3BPNODE, *PINT3BPNODE;

	list<INT3BPNODE>		g_Int3BpList;	//��ͨ�ϵ�����
	list<BPNODE>			g_MemBplist;		//�ڴ�ϵ�����
	map<DWORD, DWORD>		g_MemPagMap;		//�ڴ��ҳ���Ա�ǰ��Ϊ�ڴ��ҳ��ʼ��ַ������Ϊ������ڴ��ҳ����
	DWORD	g_dwBpOrder = 0;				//�ϵ���Ŵ�0��ʼ����
	list<DLLNODE>			DllList;			//ģ������
	map<DWORD, CString>		ApiExportNameMap;		//ģ�鵼����������
	// 	static BOOL isSystemBreak;
	//�Ƿ���ϵͳ�ϵ�
	BOOL isSystemBreak = TRUE;
// 	HANDLE hThread;
// 	HANDLE m_pi.hProcess;
// 	CONTEXT context;

	//�Ƿ�ָ�int3�ϵ�(ֻ�ǳ����ж�,����Ҫ������ʧЧ�ϵ�)
	BOOL isResumeInt3Bp = FALSE;
	BOOL isResumeHardBp = FALSE;
	BOOL isResumeMemBp = FALSE;

	/*
	BPNODE HardBp[4] = { {1,FALSE}, {2,FALSE}, {3,FALSE}, {4,FALSE} };				//4��Ӳ���ϵ���Ϣ
	�����������ṹ�岻�ܳ�ʼ��,��������Ӳ���ϵ�ʱʧ��,���ڹ��캯���вųɹ�.
	*/
	BPNODE HardBp[4];				//4��Ӳ���ϵ���Ϣ
	DWORD	dwBpOrder = 0;				//�ϵ���Ŵ�0��ʼ����

	//�����Ƿ�Ϊ�û���������,����Ǵ���int3,����Ӳ��,�ڴ�ϵ�����������FALSE
	//�ڵ�������,������������ΪTRUE
	BOOL isUserStep = FALSE;	
// 	DWORD	dwShowDataAddr = 0;		//����������ʾ��ַ
	/*g_dwShowDataAddr
	//my-���ø�������Ϊִ��D(��߲�����ַ)�����,��Ҫ���µ�ǰ��ַ�������ʾ��,
	����g_dwShowDisasmAddrͬ�����
	*/
// 	DWORD	dwShowDisasmAddr = 0;		//��������������ʾ��ַ

	//////////////////////////////////////////////////////////////////////////
	LPDEBUG_EVENT m_pDbgEvt;
	PROCESS_INFORMATION m_pi;
	LPVOID m_lpBaseOfImage;
	WCHAR *szPath=nullptr;
private:
	//������Ϣ�ַ�
	DWORD DispatchDbgEvent( DEBUG_EVENT &DebugEvent);
	//��������
	DWORD OnCreateProcess(DEBUG_EVENT& DebugEvent);
	//�쳣�ַ�
	DWORD DispatchException( DEBUG_EVENT &DebugEvent );
	//int3�쳣
	DWORD OnExceptionInt3Bp( DEBUG_EVENT &DebugEvent );
	//�����쳣//Ӳ���쳣
	DWORD OnExceptionSingleStep( DEBUG_EVENT &DebugEvent );
	//����INT3�ϵ�
	DWORD CmdSetInt3BP( DWORD dwAddress, BOOL IsAlways=TRUE );
	//���������ϵ�
	DWORD CmdSetIfBp ( DWORD dwStartAddress,DWORD dwEndAdderss );
	//��ʾint3�ϵ�
	DWORD CmdShowGeneralBPList();
	//ɾ��int3�ϵ�
	DWORD CmdDelGeneralBP( DWORD dwOrder );
	//����
	DWORD CmdShowHelp();
	//��������
	DWORD CmdStepInto();
	//����
	DWORD CmdRun();
	//��������
	DWORD CmdStepOver( DEBUG_EVENT &DebugEvent);
	//���һ��ָ��
	DWORD DisasmOneCode(HANDLE hProcess, LPVOID pCodeAddr, CString *szDisasm);
	//��ʾ���ָ��//8��
	DWORD CmdShowAsmCode( DWORD dwAddr, DEBUG_EVENT &DebugEvent );
	//��ʾ����
	DWORD CmdShowData( DWORD dwAddr, DEBUG_EVENT &DebugEvent );
	//����Ӳ���ϵ�
	DWORD CmdSetHardBP( DWORD dwAddr, DWORD dwLen, CHAR *pType );
	//��ʾӲ���ϵ��б�
	DWORD CmdShowHardBPList();
	//ɾ��Ӳ���ϵ�
	DWORD CmdDelHardBP( DWORD dwOrder );
	//�����ڴ�ϵ�
	DWORD CmdSetMemBP( DWORD dwAddr, DWORD dwLen, CHAR *pType );
	//������һ����ҳ���ڵ��ڴ�ϵ�
	DWORD SetMemBpOnOnePag(LPVOID lpBpAddr, DWORD dwLen, BP_RWE enuMemBpRwe);
	//��ʾ�ڴ�ϵ�
	DWORD CmdShowMemBPList();
	DWORD CmdShowPagMemBPList();
	//ɾ���ڴ�ϵ�
	DWORD CmdDelMemBP( DWORD dwOrder );
	//�ڴ�����쳣
	DWORD OnExceptionAccess( DEBUG_EVENT &DebugEvent );
	//��ʾģ��
	DWORD CmdShowMod( DEBUG_EVENT &DebugEvent );
	//�õ���ǰģ��
	BOOL GetCurrentModules( DEBUG_EVENT &DebugEvent );
	//��ʾ������
	DWORD CmdShowExportTable();
	//��ʾ�����
	DWORD CmdShowImportTable();
	//��ʾһ�����ָ��
	DWORD ShowDisasmOneCode( LPVOID pCodeAddr);
	//�û�����
	DWORD UserInput( DEBUG_EVENT &DebugEvent );
	//��ӡ�Ĵ���
	void ShowRegInfo ( LPCONTEXT lpContext );
	//��ʾ�Ĵ���
	DWORD CmdShowReg();
	//��ʾ��ջ
	DWORD CmdShowStack ();
	//����dll
	DWORD OnLoadDll( DEBUG_EVENT &DebugEvent);
	//RVA->offset
	DWORD RVAToOffset ( IMAGE_DOS_HEADER* pDos, DWORD dwRva );
};

