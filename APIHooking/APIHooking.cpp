// APIHooking.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "APIHooking.h"


// This is an example of an exported variable
APIHOOKING_API int nAPIHooking=0;

// This is an example of an exported function.
APIHOOKING_API int fnAPIHooking(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CAPIHooking::CAPIHooking()
{
    return;
}
