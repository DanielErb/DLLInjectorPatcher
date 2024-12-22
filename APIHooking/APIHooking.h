// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the APIHOOKING_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// APIHOOKING_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef APIHOOKING_EXPORTS
#define APIHOOKING_API __declspec(dllexport)
#else
#define APIHOOKING_API __declspec(dllimport)
#endif

// This class is exported from the dll
class APIHOOKING_API CAPIHooking {
public:
	CAPIHooking(void);
	// TODO: add your methods here.
};

extern APIHOOKING_API int nAPIHooking;

APIHOOKING_API int fnAPIHooking(void);
