#pragma warning(push, 0)  // Push current warning state and set it to 0 (off)


#include "driver.h"


// Global Vars
OB_CALLBACK_REGISTRATION  ObRegistration = { 0 };
OB_OPERATION_REGISTRATION OperationRegistrations[2] = { { 0 }, { 0 } };
UNICODE_STRING Altitude = { 0 };
//  The following are for setting up callbacks for Process and Thread filtering
PVOID RegistrationHandle = NULL;
TD_CALLBACK_REGISTRATION CallbackRegistration = { 0 };



NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UINT64 uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("\n[*] DriverEntry Called.\n");

	DbgPrint("[*] Setting Devices major function for unload.\n");
	pDriverObject->DriverUnload = DrvUnload;

	// ==============================================

	 // Setup the Ob Registration calls
	OperationRegistrations[0].ObjectType = PsProcessType;
	OperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	OperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	OperationRegistrations[0].PreOperation = PreOperationCallback;
	OperationRegistrations[0].PostOperation = PostOperationCallback;

	OperationRegistrations[1].ObjectType = PsThreadType;
	OperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	OperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	OperationRegistrations[1].PreOperation = PreOperationCallback;
	OperationRegistrations[1].PostOperation = PostOperationCallback;


	RtlInitUnicodeString(&Altitude, L"12345");

	ObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	ObRegistration.OperationRegistrationCount = 2;
	ObRegistration.Altitude = Altitude;
	ObRegistration.RegistrationContext = &CallbackRegistration;
	ObRegistration.OperationRegistration = OperationRegistrations;


	NtStatus = ObRegisterCallbacks(
		&ObRegistration,
		&RegistrationHandle       // save the registration handle to remove callbacks later
	);
	
	DbgPrint("\n\n====================== [!]Address info from Test Drier Start ========================\n\n");

	DbgPrint("[+]Address of PreOperation for process type callback function: 0x%llp\n", OperationRegistrations[0].PreOperation);
	DbgPrint("[+]Address of PostOperation for process type callback function: 0x%llp\n", OperationRegistrations[0].PostOperation);

	DbgPrint("[+]Address of PreOperation for thread type callback function: 0x%llp\n", OperationRegistrations[1].PreOperation);
	DbgPrint("[+]Address of PostOperation for thread type callback function: 0x%llp\n", OperationRegistrations[1].PostOperation);

	DbgPrint("\n====================== [!]Address info from Test Drier End ========================\n\n");


	return NtStatus;
}

VOID DrvUnload(PDRIVER_OBJECT  DriverObject)
{
	// Unregistering callback
	ObUnRegisterCallbacks(RegistrationHandle);
}
