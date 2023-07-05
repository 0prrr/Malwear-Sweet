/*
*
* Use COM object 13709620-C279-11CE-A49E-444553540000 (ShellExecute) function
* to execute command
*
*/

#include <windows.h>
#include <stdio.h>
#include <initguid.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

DEFINE_GUID(clsid, 0x13709620, 0xc279, 0x11ce, 0xa4, 0x9e, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);

// comment out to suppress output
//
#define _DBG

#ifdef _DBG
#define DLOG(x, ...) printf(x, ##__VA_ARGS__)
#define _INT getchar()
#else
#define DLOG(x, ...)
#define _INT
#endif

int main()
{
    HRESULT hRes = 0x0;
    IDispatch* pDispatch = NULL;
    DISPID dispid = 0x0;
    VARIANT varArgs = { VT_EMPTY };

    hRes = CoInitialize(NULL);
    if (FAILED(hRes))
    {
        DLOG("[-]Failed to initialize COM object ...\n");
        return -1;
    }

    // Create an instance of Shell Automation Service object dispath
    hRes = CoCreateInstance(&clsid, NULL, CLSCTX_ALL, &IID_IDispatch, (VOID**)&pDispatch);
    if (FAILED(hRes))
    {
        //DLOG("[-]Failed to create ShellWindows object ...\n");
        DLOG("[-]Failed to create Shell Automation Service object ... 0x%.8x\n", hRes);
        goto _exit;
    }

    DLOG("[*]Dispatch: %p\n", pDispatch);

    // Get DISPID of ShellExecute function
    WCHAR* szMember = L"ShellExecute";
    hRes = pDispatch->lpVtbl->GetIDsOfNames(pDispatch, &IID_NULL, &szMember, 1, LOCALE_USER_DEFAULT, &dispid);
    if (FAILED(hRes))
    {
        DLOG("[-]Failed to get DISPID of ShellExecute function ... 0x%.8x\n", hRes);
        goto _exit;
    }

    DLOG("[*]DispatchID: %ld\n", dispid);

    varArgs.vt = VT_BSTR;
    varArgs.bstrVal = SysAllocString(L"c:\\windows\\system32\\calc");
    DISPPARAMS dp = { &varArgs, NULL, 1, 0 };
    VARIANT output = { VT_EMPTY };

    // Invoke ShellExecute function
    hRes = pDispatch->lpVtbl->Invoke(pDispatch, dispid, &IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dp, &output, NULL, NULL);
    if (FAILED(hRes))
    {
        DLOG("[-]Failed to invoke ShellExecute function ... 0x%.8x\n", hRes);
        goto _exit;
    }

_exit:
    // Cleanup
    if (NULL != pDispatch)
        pDispatch->lpVtbl->Release(pDispatch);
    // Free BSTRs
    SysFreeString(varArgs.bstrVal);
    // Uninitialize COM interface
    CoUninitialize();

    return 0;
}
