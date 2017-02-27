//taken from http://www.openrce.org/blog/view/1719/Visual_Basic_6_IDC_updated
//Here's the VB6 IDC from Reginald Wong update.

/*
// File:
//   vb.idc (for Visual Basic 5/6)
//
// Created by:
//   Reginald Wong (reginaldw[at]trendmicro[dot]com[dot]ph)
// Updated by:
//   Bernard Sapaden (bsapaden[at]gmail[dot]com)
//
// Purpose:
//   This is my first idc that will
//   show the vb header in some detail
//	points out execute points of events from modules, forms, objects...
//
// Usage:
//   Run IDC script after initial autoanalysis.
//
// References:
//   DISASSEMBLING VISUAL BASIC APPLICATIONS by Sanchit Karve
//   Virus Bulletin January 2002
//   Virus Bulletin June 2002
//   Visual Basic Image Internal Structure Format by Alex Ionescu
//   VISUAL BASIC REVERSED - A decompiling approach by AndreaGeddon
//
// Notes:
//   For better formatting, set the number of opcode bytes to 4, 
//    instruction indentation to 60 and comments indentation to 100 
//    in the Disassemly tab of general options.
//
//   This script still needs to be enhanced and I'll still continue updating.
//   Still buggy.
//   Mabuhay Pilipinas!!!
//
// Updates by: Bernard Sapaden
//   Added EventHandler Structure
//	Added Detection of Control type
//	Added Detection of Events per control type
//   Added Detection of Method vs Event handler
//   Added labels and objects names of each known structure
//	Improved readability and comments
//	etc.
// 
*/

#include <idc.idc>

//
// Macros
//

static SetNameComm(ea,varname,comment){
MakeName(ea,varname);
MakeComm(ea,comment);
}

static FixByte(ea,varname,comment){
MakeByte(ea);
SetNameComm(ea,varname,comment);
}
static FixWord(ea,varname,comment){
MakeWord(ea);
SetNameComm(ea,varname,comment);
}
static FixDword(ea,varname,comment){
MakeDword(ea);
SetNameComm(ea,varname,comment);
}

//
// Create an array of 0x10 bytes for UUID
// --------------------------------------
// FixUUID(
//	ea,	// linear address
//	varname,	// name for this UUID
//	comment,	// comment
//	);
//
static FixUUID(ea,varname,comment)
{
MakeArray(ea,0x10);
SetNameComm(ea,varname,comment);
}

//
// Create a string, Rename an address and Set comment 
// --------------------------------------------------
// FixStr(
//	ea,	// linear address  (for MakeStr)
//	endea,	// ending address of the string (for MakeStr)
//	varname,	// name for the variable (for MakeName)
//	comment,	// comment (for MakeComm)
//	);
//  
// e.g.	FixStr(ea+0x00, ea+0x04, "szVbMagic" + "_" + catstring, "“VB5!” String");
//
static FixStr(ea,endea,varname,comment)
{
MakeStr(ea,endea);
SetNameComm(ea,varname,comment);
}

//
// Delete any names in an area of bytes
// ------------------------------------
// ClearUnknown(
//	ea,	// linear address
//	size,	// number of bytes
//	);
//
// e.g. ClearUnknown(ea,0x68)
//
static ClearUnknown(ea,size)
{
auto clearcounter;

// delete names with "this size" of bytes
MakeUnknown(ea,size,0x02);

// set names to "" 
for(clearcounter=0;clearcounter<size;clearcounter++)
{
MakeName(ea+clearcounter,"");
}	
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// VB header structure
//
static FixVBHeader(ea,catstring)
{	

ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| VB Header ");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");


ClearUnknown(ea,0x68);
FixStr          (ea + 0x00, ea + 0x04,             catstring        + "_" + "szVbMagic"            ,                "“VB5!” String");
FixWord         (ea + 0x04,                        catstring        + "_" + "wRuntimeBuild"        ,                "Build of the VB6 Runtime");
FixStr          (ea + 0x06, ea + 0x14,             catstring        + "_" + "szLangDll"            ,                "Language Extension DLL");
FixStr          (ea + 0x14, ea + 0x22,             catstring        + "_" + "szSecLangDll"         ,                "2nd Language Extension DLL");
FixWord         (ea + 0x22,                        catstring        + "_" + "wRuntimeRevision"     ,                "Internal Runtime Revision");
FixDword        (ea + 0x24,                        catstring        + "_" + "dwLCID"               ,                "LCID of Language DLL");
FixDword        (ea + 0x28,                        catstring        + "_" + "dwSecLCID"            ,                "LCID of 2nd Language DLL");
FixDword        (ea + 0x2C,                        catstring        + "_" + "lpSubMain"            ,                "Pointer to Sub Main Code");
FixDword        (ea + 0x30,                        catstring        + "_" + "lpProjectData"        ,                "Pointer to Project Data");
FixDword        (ea + 0x34,                        catstring        + "_" + "fMdlIntCtls"          ,                "VB Control Flags for IDs < 32");
FixDword        (ea + 0x38,                        catstring        + "_" + "fMdlIntCtls2"         ,                "VB Control Flags for IDs > 32");
FixDword        (ea + 0x3C,                        catstring        + "_" + "dwThreadFlags"        ,                "Threading Mode");
FixDword        (ea + 0x40,                        catstring        + "_" + "dwThreadCount"        ,                "Threads to support in pool");
FixWord         (ea + 0x44,                        catstring        + "_" + "wFormCount"           ,                "Number of forms present");
FixWord         (ea + 0x46,                        catstring        + "_" + "wExternalCount"       ,                "Number of external controls");
FixDword        (ea + 0x48,                        catstring        + "_" + "dwThunkCount"         ,                "Number of thunks to create");
FixDword        (ea + 0x4C,                        catstring        + "_" + "lpGuiTable"           ,                "Pointer to GUI Table");
FixDword        (ea + 0x50,                        catstring        + "_" + "lpExternalTable"      ,                "Pointer to External Table");
FixDword        (ea + 0x54,                        catstring        + "_" + "lpComRegisterData"    ,                "Pointer to COM Information");
FixDword        (ea + 0x58,                        catstring        + "_" + "bSZProjectDescription",                "Offset to Project Description");
FixDword        (ea + 0x5C,                        catstring        + "_" + "bSZProjectExeName"    ,                "Offset to Project EXE Name");
FixDword        (ea + 0x60,                        catstring        + "_" + "bSZProjectHelpFile"   ,                "Offset to Project Help File");
FixDword        (ea + 0x64,                        catstring        + "_" + "bSZProjectName"       ,                "Offset to Project Name");

//
// Add entrypoint of sub_main if exists...
//
if(Dword(ea+0x2c) != 0)
{
AddEntryPoint(Dword(ea+0x2c),Dword(ea+0x2c),"Sub_Main",1);
}
Message("--> Done fixing vbheader structure.\n");
}                                                    

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Com Registration Data structure
//
static FixCOMRegistrationData(ea,catstring)
{
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Com Registration Data");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x30);                         
FixDword        (ea + 0x00,                        catstring        + "_" + "bRegInfo"             ,                "Offset to COM Interfaces Info");
FixDword        (ea + 0x04,                        catstring        + "_" + "bSZProjectName"       ,                "Offset to Project/Typelib Name");
FixDword        (ea + 0x08,                        catstring        + "_" + "bSZHelpDirectory"     ,                "Offset to Help Directory");
FixDword        (ea + 0x0C,                        catstring        + "_" + "bSZProjectDescription",                "Offset to Project Description");
FixUUID         (ea + 0x10,                        catstring        + "_" + "uuidProjectClsId"     ,                "CLSID of Project/Typelib");
FixDword        (ea + 0x20,                        catstring        + "_" + "dwTlbLcid"            ,                "LCID of Type Library");
FixWord         (ea + 0x24,                        catstring        + "_" + "wUnknown"             ,                "Might be something. Must check");
FixWord         (ea + 0x26,                        catstring        + "_" + "wTlbVerMajor"         ,                "Typelib Major Version");
FixWord         (ea + 0x28,                        catstring        + "_" + "wTlbVerMinor"         ,                "Typelib Minor Version");
Message("--> Done fixing comregistrationdata structure.\n");
}                                                    
            
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Com Registration Info structure
//	                                                   
static FixCOMRegistrationInfo(ea,catstring)
{         
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Com Registration Info ");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x44);                         
FixDword        (ea + 0x00,                        catstring           + "_" + "bNextObject"       ,                "Offset to COM Interfaces Info");
FixDword        (ea + 0x04,                        catstring           + "_" + "bObjectName"       ,                "Offset to Object Name");
FixDword        (ea + 0x08,                        catstring           + "_" + "bObjectDescription",                "Offset to Object Description");
FixDword        (ea + 0x0C,                        catstring           + "_" + "dwInstancing"      ,                "Instancing Mode");
FixDword        (ea + 0x10,                        catstring           + "_" + "dwObjectId"        ,                "Current Object ID in the Project");
FixUUID         (ea + 0x14,                        catstring           + "_" + "uuidObject"        ,                "CLSID of Object");
FixDword        (ea + 0x24,                        catstring           + "_" + "fIsInterface"      ,                "Specifies if the next CLSID is valid");
FixDword        (ea + 0x28,                        catstring           + "_" + "bUuidObjectIFace"  ,                "Offset to CLSID of Object Interface");
FixDword        (ea + 0x2C,                        catstring           + "_" + "bUuidEventsIFace"  ,                "Offset to CLSID of Events Interface");
FixDword        (ea + 0x30,                        catstring           + "_" + "fHasEvents"        ,                "Specifies if the CLSID above is valid");
FixDword        (ea + 0x34,                        catstring           + "_" + "dwMiscStatus"      ,                "OLEMISC Flags (see MSDN docs)");
FixByte         (ea + 0x38,                        catstring           + "_" + "fClassType"        ,                "Class Type");
FixByte         (ea + 0x39,                        catstring           + "_" + "fObjectType"       ,                "Flag identifying the Object Type");
FixWord         (ea + 0x3A,                        catstring           + "_" + "wToolboxBitmap32"  ,                "Control Bitmap ID in Toolbox");
FixWord         (ea + 0x3C,                        catstring           + "_" + "wDefaultIcon"      ,                "Minimized Icon of Control Window");
FixWord         (ea + 0x3E,                        catstring           + "_" + "fIsDesigner"       ,                "Specifies whether this is a Designer");
FixDword        (ea + 0x40,                        catstring           + "_" + "bDesignerData"     ,                "Offset to Designer Data");

Message("--> Done fixing comregistrationinfo structure.\n");
}                                                    

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Designer Info structure
//                                                     
static FixDesignerInfo(ea,catstring)
{                
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Designer Information ");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown    (ea, Dword(ea+0x10)+0x14);
FixUUID         (ea + 0x00,                        catstring         + "_" + "uuidDesigner"        ,                "CLSID of the Addin/Designer");
FixDword        (ea + 0x10,                        catstring         + "_" + "cbStructSize"        ,                "Total Size of the next fields.");
ea = ea + 0x18;                                                                                    
MakeDword       (ea - 0x04);                                                                       
FixStr          (ea, ea + Dword(ea - 0x04),        catstring         + "_" + "bstrAddinRegKey"     ,                "Registry Key of the Addin");
ea = ea + 0x04 + Dword(ea - 0x04);                                                                 
MakeDword       (ea - 0x04);                                                                       
FixStr          (ea, ea + Dword(ea - 0x04),        catstring         + "_" + "bstrAddinName"       ,                "Friendly Name of the Addin");
ea = ea + 0x04 + Dword(ea - 0x04);                                                                 
MakeDword       (ea - 0x04);                                                                       
FixStr          (ea, ea + Dword(ea - 0x04),        catstring         + "_" + "bstrAddinDescription",                "Description of Addin");
ea = ea + Dword(ea - 0x04);                                                                        
FixDword        (ea,                               catstring         + "_" + "dwLoadBehaviour"     ,                "CLSID of Object");
ea = ea + 0x08;                                                                                    
MakeDword       (ea - 0x04);                                                                       
FixStr          (ea, ea + Dword(ea - 0x04), catstring         + "_" + "bstrSatelliteDll"    ,                "Satellite DLL, if specified");
ea = ea + 0x04 + Dword(ea - 0x04);                                                                 
MakeDword       (ea - 0x04);                                                                       
FixStr          (ea, ea + Dword(ea - 0x04),        catstring         + "_" + "bstrAdditionalRegKey",                "Extra Registry Key, if specified");
ea = ea + Dword(ea - 0x04);                                                                        
FixDword        (ea,                               catstring         + "_" + "dwCommandLineSafe"   ,                "Specifies a GUI-less Addin if 1.");

Message("--> Done fixing Designer Info structure.\n");
}                                                    

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Project Information structure
//
static FixProjectInformation(ea,catstring)
{	         
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Project Information ");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x23c);                        
FixDword        (ea + 0x00,                        catstring            + "_" + "dwVersion"        ,                "5.00 in Hex (0x1F4). Version.");
FixDword        (ea + 0x04,                        catstring            + "_" + "lpObjectTable"    ,                "Pointer to the Object Table");
FixDword        (ea + 0x08,                        catstring            + "_" + "dwNull"           ,                "Unused value after compilation.");
FixDword        (ea + 0x0C,                        catstring            + "_" + "lpCodeStart"      ,                "Points to start of code. Unused.");
FixDword        (ea + 0x10,                        catstring            + "_" + "lpCodeEnd"        ,                "Points to end of code. Unused.");
FixDword        (ea + 0x14,                        catstring            + "_" + "dwDataSize"       ,                "Size of VB Object Structures. Unused.");
FixDword        (ea + 0x18,                        catstring            + "_" + "lpThreadSpace"    ,                "Pointer to Pointer to Thread Object.");
FixDword        (ea + 0x1C,                        catstring            + "_" + "lpVbaSeh"         ,                "Pointer to VBA Exception Handler");
FixDword        (ea + 0x20,                        catstring            + "_" + "lpNativeCode"     ,                "Pointer to .DATA section.");
FixStr          (ea + 0x24, ea + 0x234,            catstring            + "_" + "szPathInformation",                "Contains Path and ID string. < SP6");
FixDword        (ea + 0x234,                       catstring            + "_" + "lpExternalTable"  ,                "Pointer to External Table.");
FixDword        (ea + 0x238,                       catstring            + "_" + "dwExternalCount"  ,                "Objects in the External Table.");

Message("--> Done fixing Project Information structure.\n");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Secondary Project Information structure
//
static FixSecondaryProjectInformation(ea,catstring)
{	
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Secondary Project Information ");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x28);
FixDword        (ea + 0x00,                        catstring         + "_" + "lpHeapLink"          ,                "Unused after compilation, always 0.");
FixDword        (ea + 0x04,                        catstring         + "_" + "lpObjectTable"       ,                "Back-Pointer to the Object Table.");
FixDword        (ea + 0x08,                        catstring         + "_" + "dwReserved"          ,                "Always set to -1 after compiling. Unused");
FixDword        (ea + 0x0C,                        catstring         + "_" + "dwUnused"            ,                "Not written or read in any case.");
FixDword        (ea + 0x10,                        catstring         + "_" + "lpObjectList"        ,                "Pointer to Object Descriptor Pointers.");
FixDword        (ea + 0x14,                        catstring         + "_" + "dwUnused2"           ,                "Not written or read in any case.");
FixDword        (ea + 0x18,                        catstring         + "_" + "szProjectDescription",                "Pointer to Project Description");
FixDword        (ea + 0x1C,                        catstring         + "_" + "szProjectHelpFile"   ,                "Pointer to Project Help File");
FixDword        (ea + 0x20,                        catstring         + "_" + "dwReserved2"         ,                "Always set to -1 after compiling. Unused");
FixDword        (ea + 0x24,                        catstring         + "_" + "dwHelpContextId"     ,                "Help Context ID set in Project Settings.");

Message("--> Done fixing Secondary Project Information structure.\n");
}                                                    

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Object TAble structure
//
static FixObjectTable(ea,catstring)
{
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Object Table ");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");
               
ClearUnknown(ea,0x54);                         
FixDword        (ea + 0x00,                        catstring            + "_" + "lpHeapLink"       ,                "Unused after compilation, always 0.");
FixDword        (ea + 0x04,                        catstring            + "_" + "lpExecProj"       ,                "Pointer to VB Project Exec COM Object.");
FixDword        (ea + 0x08,                        catstring            + "_" + "lpProjectInfo2"   ,                "Secondary Project Information.");
FixDword        (ea + 0x0C,                        catstring            + "_" + "dwReserved"       ,                "Always set to -1 after compiling. Unused");
FixDword        (ea + 0x10,                        catstring            + "_" + "dwNull"           ,                "Not used in compiled mode.");
FixDword        (ea + 0x14,                        catstring            + "_" + "lpProjectObject"  ,                "Pointer to in-memory Project Data.");
FixUUID         (ea + 0x18,                        catstring            + "_" + "uuidObject"       ,                "GUID of the Object Table.");
FixWord         (ea + 0x28,                        catstring            + "_" + "fCompileState"    ,                "Internal flag used during compilation.");
FixWord         (ea + 0x2A,                        catstring            + "_" + "dwTotalObjects"   ,                "Total objects present in Project.");
FixWord         (ea + 0x2C,                        catstring            + "_" + "dwCompiledObjects",                "Equal to above after compiling.");
FixWord         (ea + 0x2E,                        catstring            + "_" + "dwObjectsInUse"   ,                "Usually equal to above after compile.");
FixDword        (ea + 0x30,                        catstring            + "_" + "lpObjectArray"    ,                "Pointer to Object Descriptors");
FixDword        (ea + 0x34,                        catstring            + "_" + "fIdeFlag"         ,                "Flag/Pointer used in IDE only.");
FixDword        (ea + 0x38,                        catstring            + "_" + "lpIdeData"        ,                "Flag/Pointer used in IDE only.");
FixDword        (ea + 0x3C,                        catstring            + "_" + "lpIdeData2"       ,                "Flag/Pointer used in IDE only.");
FixDword        (ea + 0x40,                        catstring            + "_" + "lpszProjectName"  ,                "Pointer to Project Name.");
FixDword        (ea + 0x44,                        catstring            + "_" + "dwLcid"           ,                "LCID of Project.");
FixDword        (ea + 0x48,                        catstring            + "_" + "dwLcid2"          ,                "Alternate LCID of Project.");
FixDword        (ea + 0x4C,                        catstring            + "_" + "lpIdeData3"       ,                "Flag/Pointer used in IDE only.");
FixDword        (ea + 0x50,                        catstring            + "_" + "dwIdentifier"     ,                "Template Version of Structure.");


}
                                                    
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Private Object Descriptor structure
//
static FixPrivateObjectDescriptor(counter, ea,catstring)
{     
ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"| Private Object Descriptor #0x" + ltoa(counter+1,16));
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x40);                         
FixDword        (ea + 0x00,                        catstring                + "_" + "lpHeapLink"   ,                "Unused after compilation, always 0.");
FixDword        (ea + 0x04,                        catstring                + "_" + "lpObjectInfo" ,                "Pointer to the Object Info for this Object.");
FixDword        (ea + 0x08,                        catstring                + "_" + "dwReserved"   ,                "Always set to -1 after compiling.");
FixDword        (ea + 0x0C,                        catstring                + "_" + "dwIdeData"    ,                "[3] Not valid after compilation.");
MakeDword       (ea + 0x10);                                                                       
MakeDword       (ea + 0x14);                                                                       
FixDword        (ea + 0x18,                        catstring                + "_" + "lpObjectList" ,                "Points to the Parent Structure (Array)");
FixDword        (ea + 0x1C,                        catstring                + "_" + "dwIdeData2"   ,                "Not valid after compilation.");
FixDword        (ea + 0x20,                        catstring                + "_" + "lpObjectList2",                "[3] Points to the Parent Structure (Array).");
MakeDword       (ea + 0x24);                                                                       
MakeDword       (ea + 0x28);                                                                       
FixDword        (ea + 0x2C,                        catstring                + "_" + "dwIdeData3"   ,                "[3] Not valid after compilation.");
MakeDword       (ea + 0x30);                                                                       
MakeDword       (ea + 0x34);                                                                       
FixDword        (ea + 0x38,                        catstring                + "_" + "dwObjectType" ,                "Type of the Object described.");
FixDword        (ea + 0x3C,                        catstring                + "_" + "dwIdentifier" ,                "Template Version of Structure.");

}
                                                    
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Public Object Descriptor structure
//
static FixPublicObjectDescriptor(counter, ea,catstring)
{      
auto dwMethodCount;
auto lpMethodNames;

auto lpszObjectName;
auto str;

lpszObjectName = Dword(ea + 0x18);
MakeUnkn(lpszObjectName,0);
MakeStr(lpszObjectName,4);
Message("--> lpszObjectName Value: %s\n", ltoa(lpszObjectName,16));	
str =  GetString(lpszObjectName, -1, GetStringType(lpszObjectName));


ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"|  Public Object Descriptor #0x" + ltoa(counter+1,16) + " (" + str + ")");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x30);                         
FixDword        (ea + 0x00,                        catstring               + "_" + "lpObjectInfo"  ,                "Pointer to the Object Info for this Object.");
FixDword        (ea + 0x04,                        catstring               + "_" + "dwReserved"    ,                "Always set to -1 after compiling.");
FixDword        (ea + 0x08,                        catstring               + "_" + "lpPublicBytes" ,                "Pointer to Public Variable Size integers.");
FixDword        (ea + 0x0C,                        catstring               + "_" + "lpStaticBytes" ,                "Pointer to Static Variable Size integers.");
FixDword        (ea + 0x10,                        catstring               + "_" + "lpModulePublic",                "Pointer to Public Variables in DATA section");
FixDword        (ea + 0x14,                        catstring               + "_" + "lpModuleStatic",                "Pointer to Static Variables in DATA section");
FixDword        (ea + 0x18,                        catstring               + "_" + "lpszObjectName",                "Name of the Object.");
FixDword        (ea + 0x1C,                        catstring               + "_" + "dwMethodCount" ,                "Number of Methods in Object.");
FixDword        (ea + 0x20,                        catstring               + "_" + "lpMethodNames" ,                "If present, pointer to Method names array.");
FixDword        (ea + 0x24,                        catstring               + "_" + "bStaticVars"   ,                "Offset to where to copy Static Variables.");
FixDword        (ea + 0x28,                        catstring               + "_" + "fObjectType"   ,                "Flags defining the Object Type.");
FixDword        (ea + 0x2C,                        catstring               + "_" + "dwNull"        ,                "Not valid after compilation.");


dwMethodCount = Dword(ea + 0x1c);

//
// Arrange the methodcount to Dword size and give some comments
//
if(dwMethodCount > 0)
{
for(counter=0;counter<dwMethodCount;counter++)
{

lpMethodNames = Dword(ea+0x20)+(0x04*counter);
Message("--> lpMethodNames Value: 0x%s\n",ltoa(lpMethodNames,16));
FixDword (lpMethodNames,catstring+"_lpMethodNames_" + ltoa(counter,16),"Ptr to Method Name");
}
}



}                                                    

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Object Information structure
//
static FixObjectInformation(counter, ea,catstring)
{	         

auto lpszObjectName;
auto str;

lpszObjectName = Dword(Dword(ea + 0x18)+0x18);
MakeUnkn(lpszObjectName,0);
MakeStr(lpszObjectName,4);
Message("--> lpszObjectName Value: %s\n", ltoa(lpszObjectName,16));	
str =  GetString(lpszObjectName, -1, GetStringType(lpszObjectName));

ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"|  Object Information #0x" + ltoa(counter+1,16) + " (" + str + ")");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x38);                         
FixWord         (ea + 0x00,                        catstring              + "_" + "wRefCount"      ,                "Always 1 after compilation.");
FixWord         (ea + 0x02,                        catstring              + "_" + "wObjectIndex"   ,                "Index of this Object.");
FixDword        (ea + 0x04,                        catstring              + "_" + "lpObjectTable"  ,                "Pointer to the Object Table");
FixDword        (ea + 0x08,                        catstring              + "_" + "lpIdeData"      ,                "Zero after compilation. Used in IDE only.");
FixDword        (ea + 0x0C,                        catstring              + "_" + "lpPrivateObject",                "Pointer to Private Object Descriptor.");
FixDword        (ea + 0x10,                        catstring              + "_" + "dwReserved"     ,                "Always -1 after compilation.");
FixDword        (ea + 0x14,                        catstring              + "_" + "dwNull"         ,                "Unused.");
FixDword        (ea + 0x18,                        catstring              + "_" + "lpObject"       ,                "Back-Pointer to Public Object Descriptor.");
FixDword        (ea + 0x1C,                        catstring              + "_" + "lpProjectData"  ,                "Pointer to in-memory Project Object.");
FixWord         (ea + 0x20,                        catstring              + "_" + "wMethodCount"   ,                "Number of Methods");
FixWord         (ea + 0x22,                        catstring              + "_" + "wMethodCount2"  ,                "Zeroed out after compilation. IDE only.");
FixDword        (ea + 0x24,                        catstring              + "_" + "lpMethods"      ,                "Pointer to Array of Methods.");
FixWord         (ea + 0x28,                        catstring              + "_" + "wConstants"     ,                "Number of Constants in Constant Pool.");
FixWord         (ea + 0x2A,                        catstring              + "_" + "wMaxConstants"  ,                "Constants to allocate in Constant Pool.");
FixDword        (ea + 0x2C,                        catstring              + "_" + "lpIdeData2"     ,                "Valid in IDE only.");
FixDword        (ea + 0x30,                        catstring              + "_" + "lpIdeData3"     ,                "Valid in IDE only.");
FixDword        (ea + 0x34,                        catstring              + "_" + "lpConstants"    ,                "Pointer to Constants Pool.");


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// Check for optional object information
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
// - if lpConstants points to the address after it,
//   there's no optional object information
//
if(Dword(ea+0x34) != (ea+0x38))
{
FixOptionalObjectInformation(str, counter,ea+0x38,"_O"+catstring);
}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Optional Object information
//
static FixOptionalObjectInformation(str, counter,ea,catstring)
{
auto dwControlCount;
auto wEventCount;
auto lpEvent;
auto lpEventArray;
auto lpObjectGuid2;
auto lpuuidObjectTypes;
auto dwObjectTypeGuids;
auto lpEventHdr;
auto lpEventArrayAddr;

ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"|  Optional Object Information #0x" + ltoa(counter+1,16) + " (" + str + ")");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");


ClearUnknown(ea,0x40);
FixDword        (ea + 0x00,                        catstring           + "_" + "dwObjectGuids"     ,                "How many GUIDs to Register. 2 = Designer");
FixDword        (ea + 0x04,                        catstring           + "_" + "lpObjectGuid"      ,                "Unique GUID of the Object *VERIFY*");
FixDword        (ea + 0x08,                        catstring           + "_" + "dwNull"            ,                "Unused.");
FixDword        (ea + 0x0C,                        catstring           + "_" + "lpuuidObjectTypes" ,                "Pointer to Array of Object Interface GUIDs");
FixDword        (ea + 0x10,                        catstring           + "_" + "dwObjectTypeGuids" ,                "How many GUIDs in the Array above.");
FixDword        (ea + 0x14,                        catstring           + "_" + "lpControls2"       ,                "Usually the same as lpControls.");
FixDword        (ea + 0x18,                        catstring           + "_" + "dwNull2"           ,                "Unused.");
FixDword        (ea + 0x1C,                        catstring           + "_" + "lpObjectGuid2"     ,                "Pointer to Array of Object GUIDs.");
FixDword        (ea + 0x20,                        catstring           + "_" + "dwControlCount"    ,                "Number of Controls in array below.");
FixDword        (ea + 0x24,                        catstring           + "_" + "lpControls"        ,                "Pointer to Controls Array.");
FixWord         (ea + 0x28,                        catstring           + "_" + "wEventCount"       ,                "Number of Events in Event Array.");
FixWord         (ea + 0x2A,                        catstring           + "_" + "wPCodeCount"       ,                "Number of P-Codes used by this Object.");
FixWord         (ea + 0x2C,                        catstring           + "_" + "bWInitializeEvent" ,                "Offset to Initialize Event from Event Table.");
FixWord         (ea + 0x2E,                        catstring           + "_" + "bWTerminateEvent"  ,                "Offset to Terminate Event in Event Table.");
FixDword        (ea + 0x30,                        catstring           + "_" + "lpEvents"          ,                "Pointer to Events Array.");
FixDword        (ea + 0x34,                        catstring           + "_" + "lpBasicClassObject",                "Pointer to in-memory Class Objects.");
FixDword        (ea + 0x38,                        catstring           + "_" + "dwNull3"           ,                "Unused.");
FixDword        (ea + 0x3C,                        catstring           + "_" + "lpIdeData"         ,                "Only valid in IDE.");

//
// make names for lpuuidObjectTypes
//
dwObjectTypeGuids = Dword(ea + 0x10);
Message("--> dwObjectTypeGuids Value: 0x%s\n", ltoa(dwObjectTypeGuids,16));	

if(dwObjectTypeGuids > 0)
{
for(counter=0; counter < dwObjectTypeGuids; counter++)
{
lpuuidObjectTypes = Dword(ea + 0xC) + (0x04*counter);
Message("--> lpuuidObjectTypes Value: 0x%s\n",ltoa(lpuuidObjectTypes,16));
FixDword(lpuuidObjectTypes,catstring+"_lpuuidObjectTypes_" + ltoa(counter,16),"Ptr to GUID Data");	
}
}

lpObjectGuid2 = Dword(ea + 0x1C);
Message("--> lpObjectGuid2 Value: 0x%s\n",ltoa(lpObjectGuid2,16));
FixDword(lpObjectGuid2,catstring+"_lpObjectGuid2_" + ltoa(counter,16),"Ptr to GUID Data");	


//
// Number of controls of this Objects
//
dwControlCount = Dword(ea + 0x20);
Message("--> dwControlCount Value: 0x%s\n", ltoa(dwControlCount,16));	

if(dwControlCount > 0)
{
for(counter=0;counter<dwControlCount;counter++)
{
//
// ----------------------------------------------------
Message("\n--[ Reconstructing Control information 0x%s\n", ltoa(counter+1,16));
// ----------------------------------------------------
//
FixControlInformation(counter, Dword(ea+0x24)+(counter*0x28),
catstring+"_Ctl_Inf0x"+ltoa(counter+1,16));
}
}

//
// Count of Events of this Objects
//
wEventCount = Word(ea+0x28);
Message("--> wEventCount Value: 0x%s\n", ltoa(wEventCount,16));	

//
// Arrange the lpEvents to Dword size and give some comments
//
if((wEventCount > 0) && (wEventCount < 0xffff))
{

ExtLinA(Dword(ea+0x30),0,"|---------------------------------------------------------------------------------");
ExtLinA(Dword(ea+0x30),1,"|  Event Pointers #0x" + ltoa(wEventCount,16));
ExtLinA(Dword(ea+0x30),2,"|---------------------------------------------------------------------------------");

for(counter=0;counter<wEventCount;counter++)
{

lpEventArray = Dword(ea+0x30)+(0x04*counter);
lpEventHdr = Word(lpEventArray - 2);

if(lpEventHdr != 0xffff)  //Event
{
lpEventArrayAddr = Dword(lpEventArray) + 0x05 + Dword(Dword(lpEventArray)+0x01);
Message("--> lpEventArray (Event) Value: 0x%s\n",ltoa(lpEventArray,16));
FixDword (lpEventArray,catstring+"_lpEvent_" + ltoa(counter,16), "Jmp to Event Addr 0x" + ltoa(lpEventArrayAddr,16));
}
else
{
lpEventArrayAddr = Dword(lpEventArray) + 0x05 + Dword(Dword(lpEventArray)+0x01);
Message("--> lpEventArray (Method)Value: 0x%s\n",ltoa(lpEventArray,16));
FixDword (lpEventArray,catstring+"_lpMethod_" + ltoa(counter,16), "Jmp to Method Addr 0x" + ltoa(lpEventArrayAddr,16));
}
}
}


//
// Add the Event/s the entry point list
//
for(counter=0;counter<wEventCount;counter++)
{
lpEvent = Dword(Dword(ea+0x30)+(0x04*counter));
lpEventHdr = Word(Dword(ea+0x30)+(0x04*counter) - 2);

//
// validate ea (effective address)
//
if(isLoaded(lpEvent) == 1)
{
//
// this should be a jump instruction
//
if(Byte(lpEvent)==0xe9)
{

if(lpEventHdr != 0xffff)  //Event
{
lpEvent = lpEvent + 0x05 + Dword(lpEvent+0x01); //jmp instruction (e9 opcode)
Message("--> lpEvent#0x%s Address: 0x%s\n", ltoa(counter,16), ltoa(lpEvent,16));	
AddEntryPoint(lpEvent,lpEvent,catstring+"_Event0x"+ltoa(counter+1,16),1);
}
else
{
lpEvent = lpEvent + 0x05 + Dword(lpEvent+0x01); //jmp instruction (e9 opcode)
Message("--> lpMethod#0x%s Address: 0x%s\n", ltoa(counter,16), ltoa(lpEvent,16));	
AddEntryPoint(lpEvent,lpEvent,catstring+"_Method0x"+ltoa(counter+1,16),1);

  	}
  }
}
}	
}                                                    
                                                   
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Control Information structure
//
static FixControlInformation(counter,ea,catstring)
{
auto wEventHandlerCount;
auto address;
auto lpszName;
auto lpGuid;
auto str;

lpszName = Dword(ea + 0x20);
MakeUnkn(lpszName,0);
MakeStr(lpszName,4);
Message("--> lpszName Value: %s\n", ltoa(lpszName,16));	
str =  GetString(lpszName, -1, GetStringType(lpszName));

ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"|  Control Information #0x" + ltoa(counter+1,16) + " (" + str + ")");
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");

ClearUnknown(ea,0x28);                         
FixWord         (ea + 0x00,                        catstring               + "_" + "wFlagImplement"       ,                "FlagImplement.");
FixWord         (ea + 0x02,                        catstring               + "_" + "wEventHandlerCount"   ,                "Number of Events Handlers.");
FixWord         (ea + 0x04,                        catstring          	+ "_" + "wFlagIndexRef"	,                "Flag2.");
FixWord         (ea + 0x06,                        catstring               + "_" + "bWEventsOffset"       ,                "Offset in to Memory struct to copy Events.");
FixDword        (ea + 0x08,                        catstring               + "_" + "lpGuid"               ,                "Pointer to GUID of this Control.");
FixDword        (ea + 0x0C,                        catstring               + "_" + "dwIndex"              ,                "Index ID of this Control.");
FixDword        (ea + 0x10,                        catstring               + "_" + "dwNull"               ,                "Unused.");
FixDword        (ea + 0x14,                        catstring               + "_" + "dwNull2"              ,                "Unused.");
FixDword        (ea + 0x18,                        catstring               + "_" + "lpEventHandlerTable"  ,                "Pointer to Event Handler Table.");
FixDword        (ea + 0x1C,                        catstring               + "_" + "lpIdeData"            ,                "Valid in IDE only.");
FixDword        (ea + 0x20,                        catstring               + "_" + "lpszName"             ,                "Name of this Control.");
FixDword        (ea + 0x24,                        catstring               + "_" + "dwIndexCopy"          ,                "Secondary Index ID of this Control.");

lpGuid = Dword(ea + 0x08);
MakeUnkn(lpGuid,0);
FixUUID(lpGuid, "lpGUID_of_"+str, "GUID for this control");
Message("--> Done reconstructing control information structure...\n");

//
// ----------------------------------------------
Message("\n--[ Reconstructing Event Handler Table: 0x%s at 0x%s\n",ltoa(counter+1,16), ltoa(Dword(ea+0x18)+(counter*0x1c),16));
// ----------------------------------------------
//
address = Dword(ea+0x18);	// lpEventHandlerTable
FixEventHandlerTable(address, catstring+"_Evt",str);


//
// Getting Number of event handlers for this control (or pointers to their actual code)
//
wEventHandlerCount = Word(ea + 0x02);
Message("--> wEventHandlerCount Value: %s\n", ltoa(wEventHandlerCount,16));	
address = Dword(ea+0x18)+0x18;	// very first address of the first lpEventHandler

if(wEventHandlerCount != 0)
{
for(counter=0;counter<wEventHandlerCount;counter++)
{

//
// --------------------------------------------------------------------------------------------------------
Message("\n--[ Looking up event handler type: 0x%s at 0x%s\n",ltoa(counter+1,16), ltoa(Dword(address),16));
// --------------------------------------------------------------------------------------------------------
//
FixEventHandlerType(lpGuid, counter, address, catstring+"_0x"+ltoa(counter+1,16));
address = address+0x04;
}
}

}	

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Event Handler Table structure
//
static FixEventHandlerTable(ea,catstring,str)
{          
auto address;

ExtLinA(ea,0,"|---------------------------------------------------------------------------------");
ExtLinA(ea,1,"|  Event Handler Table for " + str);
ExtLinA(ea,2,"|---------------------------------------------------------------------------------");


ClearUnknown(ea,0x18);                         
FixDword        (ea + 0x00,                        catstring	+ "_" + "dwNull"	,                "Always Null.");
FixDword        (ea + 0x04,                        catstring               + "_" + "lpControlType" ,                "Pointer to control type.");
FixDword        (ea + 0x08,                        catstring               + "_" + "lpObjectInfo"  ,                "Pointer to object info.");
FixDword        (ea + 0x0C,                        catstring               + "_" + "lpQuery"       ,                "Jump to EVENT_SINK_QueryInterface.");
FixDword        (ea + 0x10,                        catstring               + "_" + "lpAddRef"      ,                "Jump to EVENT_SINK_AddRef.");
FixDword        (ea + 0x14,                        catstring               + "_" + "lpRelease"     ,                "Jump to EVENT_SINK_Release.");
Message("--> Done reconstructing event table structure...\n");

  address = Dword(ea + 0x0C);
SetNameComm(address,"lpQueryInterface","Jump to EVENT_SINK_QueryInterface.");	

  address = Dword(ea + 0x10);
SetNameComm(address,"lpAddRef","Jump to EVENT_SINK_AddRef.");

  address = Dword(ea + 0x14);
SetNameComm(address,"lpRelease","Jump to EVENT_SINK_Release.");

}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Event Handler Types structure
//
// todo: generate list of guid vs event_type
//
static FixEventHandlerType(lpGuid, counter, ea, catstring)
{          
auto address;
auto lpCode;
auto str;

ClearUnknown(ea,0x04);                         
lpCode = Dword(ea) + 0x0d+ Dword(Dword(ea) + 0x09) ; 
FixDword(Dword(ea), "Hdr_Jmp_Addr_0x" + ltoa(lpCode,16), "Flags and Code Address");

// -----------------------------------------
// command button GUID = 0x11 Events
// -----------------------------------------
if((Dword(lpGuid+0x00) == 0x33AD4EF2)  && (Dword(lpGuid+0x04) == 0x11cf6699) && (Dword(lpGuid+0x08) == 0xaa000cb7) && (Dword(lpGuid+0x0c) == 0x93d36000))
{
if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpButton_Click" , "Ptr to Button Click Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpButton_DragDrop" , "Ptr to Button DragDrop Event Code.");
}
else if(counter ==  0x2)	// Event #2
{
FixDword(ea, catstring + "_" + "lpButton_DragOver" , "Ptr to Button DragOver Event Code.");
}
else if(counter ==  0x3)	// Event #3
{
FixDword(ea, catstring + "_" + "lpButton_GotFocus" , "Ptr to Button GotFocus Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_KeyDown" , "Ptr to Button KeyDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_KeyPress" , "Ptr to Button KeyPress Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_KeyUp" , "Ptr to Button KeyUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_LostFocus" , "Ptr to Button LostFocus Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_MouseDown" , "Ptr to Button MouseDown Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_MouseMove" , "Ptr to Button MouseMove Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_MouseUp" , "Ptr to Button MouseUp Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_OLEDragOver" , "Ptr to Button OLEDragOver Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_OLEDragDrop" , "Ptr to Button OLEDragDrop Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_OLEGiveFeedback" , "Ptr to Button OLEGiveFeedback Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_OLEStartDrag" , "Ptr to Button OLEStartDrag Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_OLESetData" , "Ptr to Button OLESetData Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpButton_OLECompleteDrag" , "Ptr to Button OLECompleteDrag Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

}


// -----------------------------------------
// Drive GUID = 0x10 Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F52)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpDrive_Change" , "Ptr to Drive Change Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpDrive_DragDrop" , "Ptr to Drive DragDrop Event Code.");
}
else if(counter ==  0x2)	// Event #2
{
FixDword(ea, catstring + "_" + "lpDrive_DragOver" , "Ptr to Drive DragOver Event Code.");
}
else if(counter ==  0x3)	// Event #3
{
FixDword(ea, catstring + "_" + "lpDrive_GotFocus" , "Ptr to Drive GotFocus Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_KeyDown" , "Ptr to Drive KeyDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_KeyPress" , "Ptr to Drive KeyPress Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_KeyUp" , "Ptr to Drive KeyUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_LostFocus" , "Ptr to Drive LostFocus Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_OLEDragOver" , "Ptr to Drive OLEDragOver Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_OLEDragDrop" , "Ptr to Drive OLEDragDrop Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_OLEGiveFeedback" , "Ptr to Drive OLEGiveFeedback Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_OLEStartDrag" , "Ptr to Drive OLEStartDrag Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_OLESetDrive" , "Ptr to Drive OLESetDrive Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_OLECompleteDrag" , "Ptr to Drive OLECompleteDrag Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_Scroll" , "Ptr to Drive Scroll Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpDrive_Validate" , "Ptr to Drive Validate Event Code.");
}

else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}
}


// -----------------------------------------
// VScroll GUID = 0x0A Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F22)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpVscroll_Change" , "Ptr to Vscroll Change Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpVscroll_DragDrop" , "Ptr to Vscroll DragDrop Event Code.");
}
else if(counter ==  0x2)	// Event #2
{
FixDword(ea, catstring + "_" + "lpVscroll_DragOver" , "Ptr to Vscroll DragOver Event Code.");
}
else if(counter ==  0x3)	// Event #3
{
FixDword(ea, catstring + "_" + "lpVscroll_GotFocus" , "Ptr to Vscroll GotFocus Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpVscroll_KeyDown" , "Ptr to Vscroll KeyDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpVscroll_KeyPress" , "Ptr to Vscroll KeyPress Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpVscroll_KeyUp" , "Ptr to Vscroll KeyUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpVscroll_LostFocus" , "Ptr to Vscroll LostFocus Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpVscroll_Scroll" , "Ptr to Vscroll Scroll Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpVscroll_Validate" , "Ptr to Vscroll Validate Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}	
}



// -----------------------------------------
// File GUID = 0x16 Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F62)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpFile_Click" , "Ptr to File Click Event Code.");
}
else if(counter == 0x1)	//
{
FixDword(ea, catstring + "_" + "lpFile_DblClick" , "Ptr to File DblClick Event Code.");
}
else if(counter == 0x2)	// 
{
FixDword(ea, catstring + "_" + "lpFile_DragDrop" , "Ptr to File DragDrop Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_DragOver" , "Ptr to File DragOver Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_GotFocus" , "Ptr to File GotFocus Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_KeyDown" , "Ptr to File KeyDown Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_KeyPress" , "Ptr to File KeyPress Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_KeyUp" , "Ptr to File KeyUp Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_LostFocus" , "Ptr to File LostFocus Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_MouseDown" , "Ptr to File MouseDown Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_MouseMove" , "Ptr to File MouseMove Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_MouseUp" , "Ptr to File MouseUp Event Code.");
}

else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_PathChange" , "Ptr to File PathChange Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_PatternChange" , "Ptr to File PatternChange Event Code.");
}

else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_OLEDragOver" , "Ptr to File OLEDragOver Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_OLEDragDrop" , "Ptr to File OLEDragDrop Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_OLEGiveFeedback" , "Ptr to File OLEGiveFeedback Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_OLEStartDrag" , "Ptr to File OLEStartDrag Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_OLESetData" , "Ptr to File OLESetData Event Code.");
}
else if(counter ==  0x13)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_OLECompleteDrag" , "Ptr to File OLECompleteDrag Event Code.");
}
else if(counter ==  0x14)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_Scroll" , "Ptr to File Scroll Event Code.");
}
else if(counter ==  0x15)	// Event #
{
FixDword(ea, catstring + "_" + "lpFile_Validate" , "Ptr to File Validate Event Code.");
}

else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}	

}



// -----------------------------------------
// Dir GUID = 0x14 Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F5A)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpDir_Change" , "Ptr to Dir Change Event Code.");
}
else if(counter == 0x1)	//
{
FixDword(ea, catstring + "_" + "lpDir_Click" , "Ptr to Dir Click Event Code.");
}
else if(counter == 0x2)	// 
{
FixDword(ea, catstring + "_" + "lpDir_DragDrop" , "Ptr to Dir DragDrop Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_DragOver" , "Ptr to Dir DragOver Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_GotFocus" , "Ptr to Dir GotFocus Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_KeyDown" , "Ptr to Dir KeyDown Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_KeyPress" , "Ptr to Dir KeyPress Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_KeyUp" , "Ptr to Dir KeyUp Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_LostFocus" , "Ptr to Dir LostFocus Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_MouseDown" , "Ptr to Dir MouseDown Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_MouseMove" , "Ptr to Dir MouseMove Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_MouseUp" , "Ptr to Dir MouseUp Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_OLEDragOver" , "Ptr to Dir OLEDragOver Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_OLEDragDrop" , "Ptr to Dir OLEDragDrop Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_OLEGiveFeedback" , "Ptr to Dir OLEGiveFeedback Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_OLEStartDrag" , "Ptr to Dir OLEStartDrag Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_OLESetData" , "Ptr to Dir OLESetData Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_OLECompleteDrag" , "Ptr to Dir OLECompleteDrag Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_Scroll" , "Ptr to Dir Scroll Event Code.");
}
else if(counter ==  0x13)	// Event #
{
FixDword(ea, catstring + "_" + "lpDir_Validate" , "Ptr to Dir Validate Event Code.");
}



else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}	

}


// -----------------------------------------
// OLE GUID = 0x10 Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0X33AD5002)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpOLE_Click" , "Ptr to OLE Click Event Code.");
}
else if(counter == 0x1)	//
{
FixDword(ea, catstring + "_" + "lpOLE_DblClick" , "Ptr to OLE DblClick Event Code.");
}
else if(counter == 0x2)	// 
{
FixDword(ea, catstring + "_" + "lpOLE_DragDrop" , "Ptr to OLE DragDrop Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_DragOver" , "Ptr to OLE DragOver Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_GotFocus" , "Ptr to OLE GotFocus Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_KeyDown" , "Ptr to OLE KeyDown Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_KeyPress" , "Ptr to OLE KeyPress Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_KeyUp" , "Ptr to OLE KeyUp Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_LostFocus" , "Ptr to OLE LostFocus Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_MouseDown" , "Ptr to OLE MouseDown Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_MouseMove" , "Ptr to OLE MouseMove Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_MouseUp" , "Ptr to OLE MouseUp Event Code.");
}
else if(counter ==  0x0c)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_Resize" , "Ptr to OLE Resize Event Code.");
}
else if(counter ==  0x0d)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_Updated" , "Ptr to OLE Updated Event Code.");
}
else if(counter ==  0x0e)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_ObjectMove" , "Ptr to OLE ObjectMove Event Code.");
}
else if(counter ==  0x0F)	// Event #
{
FixDword(ea, catstring + "_" + "lpOLE_Validate" , "Ptr to OLE Validate Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}
}






// -----------------------------------------
// Hscroll GUID = 0x0A Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F1A)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpHscroll_Change" , "Ptr to Hscroll Change Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpHscroll_DragDrop" , "Ptr to Hscroll DragDrop Event Code.");
}
else if(counter ==  0x2)	// Event #2
{
FixDword(ea, catstring + "_" + "lpHscroll_DragOver" , "Ptr to Hscroll DragOver Event Code.");
}
else if(counter ==  0x3)	// Event #3
{
FixDword(ea, catstring + "_" + "lpHscroll_GotFocus" , "Ptr to Hscroll GotFocus Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpHscroll_KeyDown" , "Ptr to Hscroll KeyDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpHscroll_KeyPress" , "Ptr to Hscroll KeyPress Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpHscroll_KeyUp" , "Ptr to Hscroll KeyUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpHscroll_LostFocus" , "Ptr to Hscroll LostFocus Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpHscroll_Scroll" , "Ptr to Hscroll Scroll Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpHscroll_Validate" , "Ptr to Hscroll Validate Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}
}


// -----------------------------------------
// Data GUID = 0x0F Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4FFA)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpData_Error" , "Ptr to Data Error Event Code.");
}
else if(counter == 0x1)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_Reposition" , "Ptr to Data Reposition Event Code.");
}
else if(counter == 0x2)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_Validate" , "Ptr to Data Validate Event Code.");
}
else if(counter == 0x3)	
{
FixDword(ea, catstring + "_" + "lpData_DragDrop" , "Ptr to Data DragDrop Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_DragOver" , "Ptr to Data DragOver Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_MouseDown" , "Ptr to Data MouseDown Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_MouseMove" , "Ptr to Data MouseMove Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_MouseUp" , "Ptr to Data MouseUp Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_Resize" , "Ptr to Data Resize Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_OLEDragOver" , "Ptr to Data OLEDragOver Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_OLEDragDrop" , "Ptr to Data OLEDragDrop Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_OLEGiveFeedback" , "Ptr to Data OLEGiveFeedback Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_OLEStartDrag" , "Ptr to Data OLEStartDrag Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_OLESetData" , "Ptr to Data OLESetData Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpData_OLECompleteDrag" , "Ptr to Data OLECompleteDrag Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}	
}


// -----------------------------------------
// Image GUID = 0x0D Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F92)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpImage_Click" , "Ptr to Image Click Event Code.");
}
else if(counter == 0x1)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_DlbClick" , "Ptr to Image DlbClick Event Code.");
}
else if(counter == 0x2)	
{
FixDword(ea, catstring + "_" + "lpImage_DragDrop" , "Ptr to Image DragDrop Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_DragOver" , "Ptr to Image DragOver Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_MouseDown" , "Ptr to Image MouseDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_MouseMove" , "Ptr to Image MouseMove Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_MouseUp" , "Ptr to Image MouseUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_OLEDragOver" , "Ptr to Image OLEDragOver Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_OLEDragDrop" , "Ptr to Image OLEDragDrop Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_OLEGiveFeedback" , "Ptr to Image OLEGiveFeedback Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_OLEStartDrag" , "Ptr to Image OLEStartDrag Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_OLESetData" , "Ptr to Image OLESetData Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpImage_OLECompleteDrag" , "Ptr to Image OLECompleteDrag Event Code.");
}



else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}
}


// -----------------------------------------
// Timer GUID = 0x01 Event
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F2A)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpTimer_Timer" , "Ptr to Timer Event Code.");
}
else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}
}



// -----------------------------------------
// Frame GUID = 0x0d Events 
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4EEA)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpFrame_DragDrop" , "Ptr to Frame DragDrop Event Code.");
}
else if(counter ==  0x1)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_DragOver" , "Ptr to Frame DragOver Event Code.");
}
else if(counter ==  0x2)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_MouseDown" , "Ptr to Frame MouseDown Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_MouseMove" , "Ptr to Frame MouseMove Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_MouseUp" , "Ptr to Frame MouseUp Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_Click" , "Ptr to Frame Click Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_DlbClick" , "Ptr to Frame DlbClick Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_OLEDragOver" , "Ptr to Frame OLEDragOver Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_OLEDragDrop" , "Ptr to Frame OLEDragDrop Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_OLEGiveFeedback" , "Ptr to Frame OLEGiveFeedback Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_OLEStartDrag" , "Ptr to Frame OLEStartDrag Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_OLESetData" , "Ptr to Frame OLESetData Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpFrame_OLECompleteDrag" , "Ptr to Frame OLECompleteDrag Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

}





// -----------------------------------------
// Checkbox GUID = 0x11 Events 
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4EFA)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{

if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpCheckbox_Click" , "Ptr to Checkbox Click Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpCheckbox_DragDrop" , "Ptr to Checkbox DragDrop Event Code.");
}
else if(counter ==  0x2)	// Event #2
{
FixDword(ea, catstring + "_" + "lpCheckbox_DragOver" , "Ptr to Checkbox DragOver Event Code.");
}
else if(counter ==  0x3)	// Event #3
{
FixDword(ea, catstring + "_" + "lpCheckbox_GotFocus" , "Ptr to Checkbox GotFocus Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_KeyDown" , "Ptr to Checkbox KeyDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_KeyPress" , "Ptr to Checkbox KeyPress Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_KeyUp" , "Ptr to Checkbox KeyUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_LostFocus" , "Ptr to Checkbox LostFocus Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_MouseDown" , "Ptr to Checkbox MouseDown Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_MouseMove" , "Ptr to Checkbox MouseMove Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_MouseUp" , "Ptr to Checkbox MouseUp Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_OLEDragOver" , "Ptr to Checkbox OLEDragOver Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_OLEDragDrop" , "Ptr to Checkbox OLEDragDrop Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_OLEGiveFeedback" , "Ptr to Checkbox OLEGiveFeedback Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_OLEStartDrag" , "Ptr to Checkbox OLEStartDrag Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_OLESetData" , "Ptr to Checkbox OLESetData Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpCheckbox_OLECompleteDrag" , "Ptr to Checkbox OLECompleteDrag Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

}





// -----------------------------------------
// Form GUID = 0x1F Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F3A)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpForm_DragDrop" , "Ptr to Form DragDrop Event Code.");
}
else if(counter == 0x1)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_DragOver" , "Ptr to Form DragOver Event Code.");
}
else if(counter ==  0x2)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_LinkClose" , "Ptr to Form LinkClose Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_LinkError" , "Ptr to Form LinkError Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_LinkExecute" , "Ptr to Form LinkExecute Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_LinkOpen" , "Ptr to Form LinkOpen Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_Load" , "Ptr to Form Load Event Code.");
}
else if(counter == 0x7)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Resize" , "Ptr to Form Resize Event Code.");
}
else if(counter == 0x8)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Unload" , "Ptr to Form Unload Event Code.");
}
else if(counter == 0x9)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_QueryUnload" , "Ptr to Form QueryUnload Event Code.");
}
else if(counter == 0xA)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Activate" , "Ptr to Form Activate Event Code.");
}
else if(counter == 0xB)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Deactivate" , "Ptr to Form Deactivate Event Code.");
}
else if(counter == 0xC)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Click" , "Ptr to Form Click Event Code.");
}
else if(counter == 0xD)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_DblClick" , "Ptr to Form DblClick Event Code.");
}
else if(counter == 0xE)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_GotFocus" , "Ptr to Form GotFocus Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_KeyDown" , "Ptr to Form KeyDown Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_KeyPress" , "Ptr to Form KeyPress Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_KeyUp" , "Ptr to Form KeyUp Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_LostFocus" , "Ptr to Form LostFocus Event Code.");
}
else if(counter ==  0x13)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_MouseDown" , "Ptr to Form MouseDown Event Code.");
}
else if(counter ==  0x14)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_MouseMove" , "Ptr to Form MouseMove Event Code.");
}
else if(counter ==  0x15)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_MouseUp" , "Ptr to Form MouseUp Event Code.");
}
else if(counter == 0x16)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Paint" , "Ptr to Form Paint Event Code.");
}
else if(counter == 0x17)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Initialize" , "Ptr to Form Initialize Event Code.");
}
else if(counter == 0x18)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpForm_Terminate" , "Ptr to Form Terminate Event Code.");
}
else if(counter ==  0x19)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_OLEDragOver" , "Ptr to Form OLEDragOver Event Code.");
}
else if(counter ==  0x1A)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_OLEDragDrop" , "Ptr to Form OLEDragDrop Event Code.");
}
else if(counter ==  0x1B)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_OLEGiveFeedback" , "Ptr to Form OLEGiveFeedback Event Code.");
}
else if(counter ==  0x1C)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_OLEStartDrag" , "Ptr to Form OLEStartDrag Event Code.");
}
else if(counter ==  0x1D)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_OLESetData" , "Ptr to Form OLESetData Event Code.");
}
else if(counter ==  0x1E)	// Event #
{
FixDword(ea, catstring + "_" + "lpForm_OLECompleteDrag" , "Ptr to Form OLECompleteDrag Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

}


// -----------------------------------------
// Picture GUID = 0x1A Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4ED2)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpPicture_Change" , "Ptr to Picture Change Event Code.");
}
else if(counter == 0x1)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_Click" , "Ptr to Picture Click Event Code.");
}
else if(counter == 0x2)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_DblClick" , "Ptr to Picture DblClick Event Code.");
}
else if(counter == 0x3)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_DragDrop" , "Ptr to Picture DragDrop Event Code.");
}
else if(counter == 0x4)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_DragOver" , "Ptr to Picture DragOver Event Code.");
}
else if(counter == 0x5)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_GotFocus" , "Ptr to Picture GotFocus Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_KeyDown" , "Ptr to Picture KeyDown Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_KeyPress" , "Ptr to Picture KeyPress Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_KeyUp" , "Ptr to Picture KeyUp Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_LinkClose" , "Ptr to Picture LinkClose Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_LinkError" , "Ptr to Picture LinkError Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_LinkOpen" , "Ptr to Picture LinkOpen Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_LostFocus" , "Ptr to Picture LostFocus Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_MouseDown" , "Ptr to Picture MouseDown Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_MouseMove" , "Ptr to Picture MouseMove Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_MouseUp" , "Ptr to Picture MouseUp Event Code.");
}
else if(counter == 0x10)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_Paint" , "Ptr to Picture Paint Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_LinkNotify" , "Ptr to Textbox LinkNotify Event Code.");
}
else if(counter == 0x12)	// Event #1 - 
{
FixDword(ea, catstring + "_" + "lpPicture_Resize" , "Ptr to Picture Resize Event Code.");
}
else if(counter ==  0x13)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_OLEDragOver" , "Ptr to Picture OLEDragOver Event Code.");
}
else if(counter ==  0x14)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_OLEDragDrop" , "Ptr to Picture OLEDragDrop Event Code.");
}
else if(counter ==  0x15)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_OLEGiveFeedback" , "Ptr to Picture OLEGiveFeedback Event Code.");
}
else if(counter ==  0x16)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_OLEStartDrag" , "Ptr to Picture OLEStartDrag Event Code.");
}
else if(counter ==  0x17)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_OLESetData" , "Ptr to Picture OLESetData Event Code.");
}
else if(counter ==  0x18)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_OLECompleteDrag" , "Ptr to Picture OLECompleteDrag Event Code.");
}
else if(counter ==  0x19)	// Event #
{
FixDword(ea, catstring + "_" + "lpPicture_Validate" , "Ptr to Picture Validate Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

}


// -----------------------------------------
// Label GUID = 0x12 Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4EDA)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	
{
FixDword(ea, catstring + "_" + "lpLabel_Change" , "Ptr to Label Change Event Code.");
}
else if(counter == 0x1)	
{
FixDword(ea, catstring + "_" + "lpLabel_Click" , "Ptr to Label Click Event Code.");
}
else if(counter == 0x2)	
{
FixDword(ea, catstring + "_" + "lpLabel_DblClick" , "Ptr to Label DblClick Event Code.");
}
else if(counter == 0x3)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpLabel_DragDrop" , "Ptr to Label DragDrop Event Code.");
}
else if(counter ==  0x4)	// Event #2
{
FixDword(ea, catstring + "_" + "lpLabel_DragOver" , "Ptr to Label DragOver Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_LinkClose" , "Ptr to Label LinkClose Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_LinkError" , "Ptr to Label LinkError Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_LinkOpen" , "Ptr to Label LinkOpen Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_MouseDown" , "Ptr to Label MouseDown Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_MouseMove" , "Ptr to Label MouseMove Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_MouseUp" , "Ptr to Label MouseUp Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_LinkNotify" , "Ptr to Label LinkNotify Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_OLEDragOver" , "Ptr to Label OLEDragOver Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_OLEDragDrop" , "Ptr to Label OLEDragDrop Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_OLEGiveFeedback" , "Ptr to Label OLEGiveFeedback Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_OLEStartDrag" , "Ptr to Label OLEStartDrag Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_OLESetData" , "Ptr to Label OLESetData Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpLabel_OLECompleteDrag" , "Ptr to Label OLECompleteDrag Event Code.");
}

else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}	
}


// -----------------------------------------
// Combo GUID = 0x13 Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F0A)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	
{
FixDword(ea, catstring + "_" + "lpCombo_Change" , "Ptr to Combo Change Event Code.");
}
else if(counter == 0x1)	
{
FixDword(ea, catstring + "_" + "lpCombo_Click" , "Ptr to Combo Click Event Code.");
}
else if(counter == 0x2)	
{
FixDword(ea, catstring + "_" + "lpCombo_DblClick" , "Ptr to Combo DblClick Event Code.");
}
else if(counter == 0x3)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpCombo_DragDrop" , "Ptr to Combo DragDrop Event Code.");
}
else if(counter ==  0x4)	// Event #2
{
FixDword(ea, catstring + "_" + "lpCombo_DragOver" , "Ptr to Combo DragOver Event Code.");
}
else if(counter ==  0x5)	// Event #2
{
FixDword(ea, catstring + "_" + "lpCombo_DropDown" , "Ptr to Combo DropDown Event Code.");
}
else if(counter ==  0x6)	// Event #3
{
FixDword(ea, catstring + "_" + "lpCombo_GotFocus" , "Ptr to Combo GotFocus Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_KeyDown" , "Ptr to Combo KeyDown Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_KeyPress" , "Ptr to Combo KeyPress Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_KeyUp" , "Ptr to Combo KeyUp Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_LostFocus" , "Ptr to Combo LostFocus Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_OLEDragOver" , "Ptr to Combo OLEDragOver Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_OLEDragDrop" , "Ptr to Combo OLEDragDrop Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_OLEGiveFeedback" , "Ptr to Combo OLEGiveFeedback Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_OLEStartDrag" , "Ptr to Combo OLEStartDrag Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_OLESetData" , "Ptr to Combo OLESetData Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_OLECompleteDrag" , "Ptr to Combo OLECompleteDrag Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_Scroll" , "Ptr to Combo Scroll Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpCombo_Validate" , "Ptr to Combo Validate Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}	
}

// -----------------------------------------
// List GUID = 0x15 Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F12)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpList_Click" , "Ptr to List Click Event Code.");
}
else if(counter == 0x1)	//
{
FixDword(ea, catstring + "_" + "lpList_DblClick" , "Ptr to List DblClick Event Code.");
}
else if(counter == 0x2)	// 
{
FixDword(ea, catstring + "_" + "lpList_DragDrop" , "Ptr to List DragDrop Event Code.");
}
else if(counter ==  0x3)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_DragOver" , "Ptr to List DragOver Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_GotFocus" , "Ptr to List GotFocus Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_KeyDown" , "Ptr to List KeyDown Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_KeyPress" , "Ptr to List KeyPress Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_KeyUp" , "Ptr to List KeyUp Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_LostFocus" , "Ptr to List LostFocus Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_MouseDown" , "Ptr to List MouseDown Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_MouseMove" , "Ptr to List MouseMove Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_MouseUp" , "Ptr to List MouseUp Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_OLEDragOver" , "Ptr to List OLEDragOver Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_OLEDragDrop" , "Ptr to List OLEDragDrop Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_OLEGiveFeedback" , "Ptr to List OLEGiveFeedback Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_OLEStartDrag" , "Ptr to List OLEStartDrag Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_OLESetData" , "Ptr to List OLESetData Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_OLECompleteDrag" , "Ptr to List OLECompleteDrag Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_Scroll" , "Ptr to List Scroll Event Code.");
}
else if(counter ==  0x13)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_ItemCheck" , "Ptr to List ItemCheck Event Code.");
}
else if(counter ==  0x14)	// Event #
{
FixDword(ea, catstring + "_" + "lpList_Validate" , "Ptr to List Validate Event Code.");
}


else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

}


// -----------------------------------------
// Option GUID = 0x13 Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4F02)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpOption_Click" , "Ptr to Option Click Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpOption_DblClick" , "Ptr to Option DblClick Event Code.");
}
else if(counter == 0x2)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpOption_DragDrop" , "Ptr to Option DragDrop Event Code.");
}
else if(counter ==  0x3)	// Event #2
{
FixDword(ea, catstring + "_" + "lpOption_DragOver" , "Ptr to Option DragOver Event Code.");
}
else if(counter ==  0x4)	// Event #3
{
FixDword(ea, catstring + "_" + "lpOption_GotFocus" , "Ptr to Option GotFocus Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_KeyDown" , "Ptr to Option KeyDown Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_KeyPress" , "Ptr to Option KeyPress Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_KeyUp" , "Ptr to Option KeyUp Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_LostFocus" , "Ptr to Option LostFocus Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_MouseDown" , "Ptr to Option MouseDown Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_MouseMove" , "Ptr to Option MouseMove Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_MouseUp" , "Ptr to Option MouseUp Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_OLEDragOver" , "Ptr to Option OLEDragOver Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_OLEDragDrop" , "Ptr to Option OLEDragDrop Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_OLEGiveFeedback" , "Ptr to Option OLEGiveFeedback Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_OLEStartDrag" , "Ptr to Option OLEStartDrag Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_OLESetData" , "Ptr to Option OLESetData Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_OLECompleteDrag" , "Ptr to Option OLECompleteDrag Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpOption_Validate" , "Ptr to Option Validate Event Code.");
}

else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}


}




// -----------------------------------------
// textbox GUID = 0x18 Events
// -----------------------------------------
else if((Dword(lpGuid+0x00) == 0x33AD4EE2)  && (Dword(lpGuid+0x04) == 0x11CF6699) && (Dword(lpGuid+0x08) == 0x0AA000CB7) && (Dword(lpGuid+0x0c) == 0x93D36000))
{
if(counter == 0x0)	// Event #0 = Click
{
FixDword(ea, catstring + "_" + "lpText_Change" , "Ptr to Textbox Change Event Code.");
}
else if(counter == 0x1)	// Event #1 - DragDrop
{
FixDword(ea, catstring + "_" + "lpText_DragDrop" , "Ptr to Textbox DragDrop Event Code.");
}
else if(counter ==  0x2)	// Event #2
{
FixDword(ea, catstring + "_" + "lpText_DragOver" , "Ptr to Textbox DragOver Event Code.");
}
else if(counter ==  0x3)	// Event #3
{
FixDword(ea, catstring + "_" + "lpText_GotFocus" , "Ptr to Textbox GotFocus Event Code.");
}
else if(counter ==  0x4)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_KeyDown" , "Ptr to Textbox KeyDown Event Code.");
}
else if(counter ==  0x5)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_KeyPress" , "Ptr to Textbox KeyPress Event Code.");
}
else if(counter ==  0x6)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_KeyUp" , "Ptr to Textbox KeyUp Event Code.");
}
else if(counter ==  0x7)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_LinkClose" , "Ptr to Textbox LinkClose Event Code.");
}
else if(counter ==  0x8)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_LinkError" , "Ptr to Textbox LinkError Event Code.");
}
else if(counter ==  0x9)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_LinkOpen" , "Ptr to Textbox LinkOpen Event Code.");
}
else if(counter ==  0xA)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_LostFocus" , "Ptr to Textbox LostFocus Event Code.");
}
else if(counter ==  0xB)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_LinkNotify" , "Ptr to Textbox LinkNotify Event Code.");
}
else if(counter ==  0xC)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_MouseDown" , "Ptr to Textbox MouseDown Event Code.");
}
else if(counter ==  0xD)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_MouseMove" , "Ptr to Textbox MouseMove Event Code.");
}
else if(counter ==  0xE)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_MouseUp" , "Ptr to Textbox MouseUp Event Code.");
}
else if(counter ==  0xF)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_Click" , "Ptr to Textbox Click Event Code.");
}
else if(counter ==  0x10)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_DblClick" , "Ptr to Textbox DblClick Event Code.");
}
else if(counter ==  0x11)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_OLEDragOver" , "Ptr to Textbox OLEDragOver Event Code.");
}
else if(counter ==  0x12)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_OLEDragDrop" , "Ptr to Textbox OLEDragDrop Event Code.");
}
else if(counter ==  0x13)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_OLEGiveFeedback" , "Ptr to Textbox OLEGiveFeedback Event Code.");
}
else if(counter ==  0x14)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_OLEStartDrag" , "Ptr to Textbox OLEStartDrag Event Code.");
}
else if(counter ==  0x15)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_OLESetData" , "Ptr to Textbox OLESetData Event Code.");
}
else if(counter ==  0x16)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_OLECompleteDrag" , "Ptr to Textbox OLECompleteDrag Event Code.");
}
else if(counter ==  0x17)	// Event #
{
FixDword(ea, catstring + "_" + "lpText_Validate" , "Ptr to Textbox Validate Event Code.");
}
else // not yet implemented...
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}
}




//
// Unknown Control Yet...
//
else
{
ClearUnknown(ea,0x04);                         
FixDword(ea + 0x00, catstring + "_" + "lpHandlerFlags" , "Ptr to Handler Flags.");

address = Dword(ea);
MakeComm(address, "Almost always constant, 0xFFFF for Method, otherwise Event.");
}

  
  Message("--> Done fixing event handler type...\n");

}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Main
//
static main()
{
auto autovalue;
auto counter;
auto lpComRegisterData;
auto bRegInfo;
auto bDesignerData;
auto lpProjectData;
auto lpObjectTable;
auto lpProjectInfo2;
auto lpObjectList;
auto lpObjectArray;
auto lpObjectInfo;
auto lpOOI;
auto dwCompiledObjects;
auto dwTotalObjects;

Indent(50);
CmtIndent(100);

//
// ----------------------------------------------
Message("\n--[ Retrieving entry point (by ordinal)\n");
// ----------------------------------------------
//
autovalue = GetEntryOrdinal(0);
Message("--| GetEntryOrdinal(0) -> (function 0 is the function index, EP)\n--> Returned: %s\n", ltoa(autovalue,16));

//
// ----------------------------------------
Message("\n--[ Retrieving entry point address\n");
// ----------------------------------------
//
autovalue = GetEntryPoint(autovalue);
Message("--| GetEntryPoint(autovalue) -> (autovalue is the ordinal)\n--> Returned: %s\n",ltoa(autovalue,16));

//
// ---------------------------------------------------------------
// Displaying script information on disassembly...
// ---------------------------------------------------------------
//
ExtLinA(autovalue+0x0a,0,";========================================================================");
ExtLinA(autovalue+0x0a,1,";VB5/6 IDC");
ExtLinA(autovalue+0x0a,2,";Author: Reginald Wong, updated by Bernard Sapaden");
ExtLinA(autovalue+0x0a,3,";Check the execute points by CTRL-E or Jump->Jump to Entry point...");
ExtLinA(autovalue+0x0a,4,";========================================================================");

//
// ----------------------------------------------
Message("\n--[ Getting Offset of VBHeader...\n");
// ----------------------------------------------
//
autovalue = GetOperandValue(autovalue,0);
Message("--| Thunder Runtime Main Parameter EXEPROJECTINFO at: %s\n",ltoa(autovalue,16));
Message("--| GetOperandValue(autovalue,0)\n--> Returned: 0x%s\n", ltoa(autovalue,16));

//
// ----------------------------------------------
Message("\n--[ Checking VB5! string...\n");
// ----------------------------------------------
//
Message("--> Returned: 0x%s:\n", ltoa(Dword(autovalue),16));
if(Dword(autovalue) != 0x21354256) return 0;

//
// ----------------------------------------------
Message("\n--[ Restructuring VB Header...\n");
// ----------------------------------------------
// 
FixVBHeader(autovalue,"_VB_Header"); //  VB Header (single instance only...)


lpComRegisterData = Dword(autovalue+0x54); //  COM Registraion Data
Message("--> lpComRegisterData Value: 0x%s\n", ltoa(lpComRegisterData,16));


if(lpComRegisterData != 0)
{

//
// ----------------------------------------------
Message("\n--[ Restructuring COM Registration Data\n");
// ----------------------------------------------
//
FixCOMRegistrationData(lpComRegisterData,"_Com_Reg_Dat");	// (single instance only...)


bRegInfo = Dword(lpComRegisterData); //  COM Registration Info 
if(bRegInfo != 0)
{

//
// ----------------------------------------------------
Message("\n--[ Restructuring COM Registration Info\n");
// ----------------------------------------------------
//
FixCOMRegistrationInfo(lpComRegisterData + bRegInfo, "_Com_Reg_Inf"); // (single instance only...)

bDesignerData = lpComRegisterData + Dword(lpComRegisterData + bRegInfo + 0x40);
Message("--> bDesignerData Value: 0x%s\n", ltoa(bDesignerData,16));

if(Dword(bDesignerData) != 0)
{

//
// ----------------------------------------------------
Message("\n--[ Restructuring Designer Information\n");
// ----------------------------------------------------
//
FixDesignerInfo(bDesignerData,"_Dsn_Inf"); // (single instance only...)

}
}
}

lpProjectData = Dword(autovalue+0x30);
Message("--> lpProjectData Value: 0x%s\n", ltoa(lpProjectData,16));

if(lpProjectData != 0)
{

//
// --------------------------------------------
Message("\n--[ Restructuring Project Information\n");
// --------------------------------------------
//
FixProjectInformation(lpProjectData, "_Prj_Inf"); // Project Information (single instance only...)

lpObjectTable = Dword(lpProjectData+0x04);
Message("--> lpObjectTable Value: 0x%s\n", ltoa(lpObjectTable,16));

if(lpObjectTable != 0)
{
//
// getting no. of objects...
//
dwCompiledObjects = Word(lpObjectTable+0x2c);
dwTotalObjects = Word(lpObjectTable+0x2a);
Message("--> dwCompiledObjects: 0x%s\n", ltoa(dwCompiledObjects,16));
Message("--> dwTotalObjects: 0x%s\n", ltoa(dwTotalObjects,16));

//
// --------------------------------------
Message("\n--[ Restructuring Object Table\n");
// --------------------------------------
//
FixObjectTable(lpObjectTable,"_Obj_Tab"); // (single instance only...)

lpProjectInfo2 = Dword(lpObjectTable+0x08);
Message("--> lpProjectInfo2 Value: 0x%s\n", ltoa(lpProjectInfo2,16));

if(lpProjectInfo2 != 0)
{
//
// ------------------------------------------------
Message("\n--[ Restructuring 2nd Project Information\n");
// ------------------------------------------------
// - 
FixSecondaryProjectInformation(lpProjectInfo2,"_Prj_Inf2"); // (single instance only...)

lpObjectList = Dword(lpProjectInfo2+0x10);
Message("--> lpObjectList Value: 0x%s\n", ltoa(lpObjectList,16));

if(lpObjectList != 0)
{
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// Enumerating compiled objects...
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// Array structures: those to be loop'd...
//
//	- {Public Object Descriptor}
//	- {Private Object Descriptor}
//	- {Object Information}
//	- {Optional Object Information}
//	- {Control Information}
//	- {Event Table}
//	- {Event Pointers}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// First, loop through all the forms
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
// 
// --> dwCompiledObjects  : Count of objects in the project
// --> dwTotalObjects : Total objects present in Project.
//
// for(counter=0;counter<dwCompiledObjects;counter++) // previous logic

//for(counter=0;counter<dwTotalObjects;counter++)
for(counter=0;counter<dwCompiledObjects;counter++) 
{
// Initialize pointer to the object list structure...
//
MakeDword(lpObjectList+(counter*0x04));

//
// ------------------------------------------------------------------------------
Message("\n--[ Restructuring Private Object Descriptor 0x%s\n",ltoa(counter+1,16));
// ------------------------------------------------------------------------------
//
FixPrivateObjectDescriptor(counter, Dword(lpObjectList+(counter*0x04)),
"_Pri_Obj_Dsc"+ltoa(counter+1,16));

//
// -------------------------------------------------------------------------
Message("\n--[ Restructuring Object Information 0x%s\n",ltoa(counter+1,16));
// -------------------------------------------------------------------------
//
FixObjectInformation(counter, Dword(Dword(lpObjectList+(counter*0x04))+0x04),
"_Pri_Obj_Inf"+ltoa(counter+1,16));

}
}
}

//
// Get the pointer to the objects Array
//
lpObjectArray = Dword(lpObjectTable+0x30);
Message("--> lpObjectArray Value: 0x%s\n", ltoa(lpObjectArray,16));

if(lpObjectArray != 0)
{
//
// ReConstruct the public object descriptor and its object information
//
for(counter=0;counter<dwTotalObjects;counter++)
{
//
// -----------------------------------------------------------------------
Message("\n--[ Restructuring Public Object Descriptor 0x%s\n",ltoa(counter+1,16));
// -----------------------------------------------------------------------
//
FixPublicObjectDescriptor(counter, lpObjectArray+(counter*0x30),"_Pub_Obj_Dsc"+ltoa(counter+1,16));

//
// ------------------------------------------------------------------
Message("\n--[ Restructuring Object Information 0x%s\n",ltoa(counter+1,16));
// ------------------------------------------------------------------
//
FixObjectInformation(counter, Dword(lpObjectArray+(counter*0x30)),"_Pub_Obj_Inf"+ltoa(counter+1,16));
}
}
}
}
Message("\n\nCheck the execute points by CTRL-E or Jump->Jump to Entry point...");
Message("\n\nDone running VB IDC\nby Reginald Wong reginaldw[at]trendmicro[dot]com[dot]ph");
Message("\nand Bernard Sapaden bsapaden[at]gmail[dot]com\n");
}


////////////////////////////////////////////////////////////////
Sample Output:
////////////////////////////////////////////////////////////////


.text:0041ADE4             |---------------------------------------------------------------------------------
.text:0041ADE4             |  Public Object Descriptor #0x1 (frmMain)
.text:0041ADE4             |---------------------------------------------------------------------------------
.text:0041ADE4 88 97 41 00 _Pub_Obj_Dsc1_lpObjectInfo                                  dd offset _Pub_Obj_Inf1_wRefCount       ; DATA XREF: .text:_Pub_Obj_Inf1_lpObjecto
.text:0041ADE4                                                                                                                 ; .text:_Obj_Tab_lpObjectArrayo
.text:0041ADE4                                                                                                                 ; Pointer to the Object Info for this Object.
.text:0041ADE8 FF FF FF FF _Pub_Obj_Dsc1_dwReserved                                    dd 0FFFFFFFFh                           ; Always set to -1 after compiling.
.text:0041ADEC 14 BE 41 00 _Pub_Obj_Dsc1_lpPublicBytes                                 dd offset dword_41BE14                  ; Pointer to Public Variable Size integers.
.text:0041ADF0 00 00 00 00 _Pub_Obj_Dsc1_lpStaticBytes                                 dd 0                                    ; Pointer to Static Variable Size integers.
.text:0041ADF4 00 00 00 00 _Pub_Obj_Dsc1_lpModulePublic                                dd 0                                    ; Pointer to Public Variables in DATA section
.text:0041ADF8 00 00 00 00 _Pub_Obj_Dsc1_lpModuleStatic                                dd 0                                    ; Pointer to Static Variables in DATA section
.text:0041ADFC 48 B2 41 00 _Pub_Obj_Dsc1_lpszObjectName                                dd offset aFrmmain                      ; Name of the Object.
.text:0041AE00 28 00 00 00 _Pub_Obj_Dsc1_dwMethodCount                                 dd 28h                                  ; Number of Methods in Object.
.text:0041AE04 E4 B0 41 00 _Pub_Obj_Dsc1_lpMethodNames                                 dd offset _Pub_Obj_Dsc1_lpMethodNames_0 ; If present, pointer to Method names array.
.text:0041AE08 FF FF 00 00 _Pub_Obj_Dsc1_bStaticVars                                   dd 0FFFFh                               ; Offset to where to copy Static Variables.
.text:0041AE0C 83 80 01 00 _Pub_Obj_Dsc1_fObjectType                                   dd 18083h                               ; Flags defining the Object Type.
.text:0041AE10 00 00 00 00 _Pub_Obj_Dsc1_dwNull                                        dd 0                                    ; Not valid after compilation.
.text:0041AE14             |---------------------------------------------------------------------------------
.text:0041AE14             |  Public Object Descriptor #0x2 (modGlobals)
.text:0041AE14             |---------------------------------------------------------------------------------
.text:0041AE14 34 76 41 00 _Pub_Obj_Dsc2_lpObjectInfo                                  dd offset _Pub_Obj_Inf2_wRefCount       ; DATA XREF: .text:_Pub_Obj_Inf2_lpObjecto
.text:0041AE14                                                                                                                 ; Pointer to the Object Info for this Object.
.text:0041AE18 FF FF FF FF _Pub_Obj_Dsc2_dwReserved                                    dd 0FFFFFFFFh                           ; Always set to -1 after compiling.
.text:0041AE1C EC C2 41 00 _Pub_Obj_Dsc2_lpPublicBytes                                 dd offset dword_41C2EC                  ; Pointer to Public Variable Size integers.
.text:0041AE20 D0 16 42 00 _Pub_Obj_Dsc2_lpStaticBytes                                 dd offset asc_4216D0                    ; Pointer to Static Variable Size integers.
.text:0041AE24 24 B0 4C 00 _Pub_Obj_Dsc2_lpModulePublic                                dd offset dword_4CB024                  ; Pointer to Public Variables in DATA section
.text:0041AE28 68 BD 4C 00 _Pub_Obj_Dsc2_lpModuleStatic                                dd offset unk_4CBD68                    ; Pointer to Static Variables in DATA section
.text:0041AE2C 50 B2 41 00 _Pub_Obj_Dsc2_lpszObjectName                                dd offset aModglobals                   ; Name of the Object.
.text:0041AE30 21 00 00 00 _Pub_Obj_Dsc2_dwMethodCount                                 dd 21h                                  ; Number of Methods in Object.
.text:0041AE34 00 00 00 00 _Pub_Obj_Dsc2_lpMethodNames                                 dd 0                                    ; If present, pointer to Method names array.
.text:0041AE38 2C 05 00 00 _Pub_Obj_Dsc2_bStaticVars                                   dd 52Ch                                 ; Offset to where to copy Static Variables.
.text:0041AE3C 01 80 01 00 _Pub_Obj_Dsc2_fObjectType                                   dd 18001h                               ; Flags defining the Object Type.
.text:0041AE40 00 00 00 00 _Pub_Obj_Dsc2_dwNull                                        dd 0                                    ; Not valid after compilation.
.text:0041AE44             |---------------------------------------------------------------------------------
.text:0041AE44             |  Public Object Descriptor #0x3 (frmAbout)
.text:0041AE44             |---------------------------------------------------------------------------------
.text:0041AE44 A0 7E 41 00 _Pub_Obj_Dsc3_lpObjectInfo                                  dd offset _Pub_Obj_Inf3_wRefCount       ; DATA XREF: .text:_Pub_Obj_Inf3_lpObjecto

...
.text:0041A054             |---------------------------------------------------------------------------------
.text:0041A054             |  Event Handler Table for mnuFileDebugProcess
.text:0041A054             |---------------------------------------------------------------------------------
.text:0041A054 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_Evt_dwNull                       dd 0                                    ; DATA XREF: .text:_O_Pub_Obj_Inf1_Ctl_Inf0x5_lpEventHandlerTableo
.text:0041A054                                                                                                                 ; Always Null.
.text:0041A058 C8 98 41 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_Evt_lpControlType                dd offset _O_Pub_Obj_Inf1_Ctl_Inf0x5_wFlagImplement ; Pointer to control type.
.text:0041A05C 88 97 41 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_Evt_lpObjectInfo                 dd offset _Pub_Obj_Inf1_wRefCount       ; Pointer to object info.
.text:0041A060 3E 35 40 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_Evt_lpQuery                      dd offset lpQueryInterface              ; Jump to EVENT_SINK_QueryInterface.
.text:0041A064 44 35 40 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_Evt_lpAddRef                     dd offset lpAddRef                      ; Jump to EVENT_SINK_AddRef.
.text:0041A068 4A 35 40 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_Evt_lpRelease                    dd offset lpRelease                     ; Jump to EVENT_SINK_Release.
.text:0041A06C 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x5_0x1_lpHandlerFlags               dd 0                                    ; Ptr to Handler Flags.
                                                            
...
.text:0041A5B0             |---------------------------------------------------------------------------------
.text:0041A5B0             |  Event Handler Table for Form
.text:0041A5B0             |---------------------------------------------------------------------------------
.text:0041A5B0 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_Evt_dwNull                      dd 0                                    ; DATA XREF: .text:_O_Pub_Obj_Inf1_Ctl_Inf0x1A_lpEventHandlerTableo
.text:0041A5B0                                                                                                                 ; Always Null.
.text:0041A5B4 10 9C 41 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_Evt_lpControlType               dd offset _O_Pub_Obj_Inf1_Ctl_Inf0x1A_wFlagImplement ; Pointer to control type.
.text:0041A5B8 88 97 41 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_Evt_lpObjectInfo                dd offset _Pub_Obj_Inf1_wRefCount       ; Pointer to object info.
.text:0041A5BC 3E 35 40 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_Evt_lpQuery                     dd offset lpQueryInterface              ; Jump to EVENT_SINK_QueryInterface.
.text:0041A5C0 44 35 40 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_Evt_lpAddRef                    dd offset lpAddRef                      ; Jump to EVENT_SINK_AddRef.
.text:0041A5C4 4A 35 40 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_Evt_lpRelease                   dd offset lpRelease                     ; Jump to EVENT_SINK_Release.
.text:0041A5C8 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1_lpForm_DragDrop             dd 0                                    ; Ptr to Form DragDrop Event Code.
.text:0041A5CC 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x2_lpForm_DragOver             dd 0                                    ; Ptr to Form DragOver Event Code.
.text:0041A5D0 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x3_lpForm_LinkClose            dd 0                                    ; Ptr to Form LinkClose Event Code.
.text:0041A5D4 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x4_lpForm_LinkError            dd 0                                    ; Ptr to Form LinkError Event Code.
.text:0041A5D8 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x5_lpForm_LinkExecute          dd 0                                    ; Ptr to Form LinkExecute Event Code.
.text:0041A5DC 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x6_lpForm_LinkOpen             dd 0                                    ; Ptr to Form LinkOpen Event Code.
.text:0041A5E0 C9 AB 41 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x7_lpForm_Load                 dd offset Hdr_Jmp_Addr_0x430C70         ; Ptr to Form Load Event Code.
.text:0041A5E4 D6 AB 41 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x8_lpForm_Resize               dd offset Hdr_Jmp_Addr_0x4312C0         ; Ptr to Form Resize Event Code.
.text:0041A5E8 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x9_lpForm_Unload               dd 0                                    ; Ptr to Form Unload Event Code.
.text:0041A5EC 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0xA_lpForm_QueryUnload          dd 0                                    ; Ptr to Form QueryUnload Event Code.
.text:0041A5F0 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0xB_lpForm_Activate             dd 0                                    ; Ptr to Form Activate Event Code.
.text:0041A5F4 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0xC_lpForm_Deactivate           dd 0                                    ; Ptr to Form Deactivate Event Code.
.text:0041A5F8 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0xD_lpForm_Click                dd 0                                    ; Ptr to Form Click Event Code.
.text:0041A5FC 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0xE_lpForm_DblClick             dd 0                                    ; Ptr to Form DblClick Event Code.
.text:0041A600 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0xF_lpForm_GotFocus             dd 0                                    ; Ptr to Form GotFocus Event Code.
.text:0041A604 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x10_lpForm_KeyDown             dd 0                                    ; Ptr to Form KeyDown Event Code.
.text:0041A608 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x11_lpForm_KeyPress            dd 0                                    ; Ptr to Form KeyPress Event Code.
.text:0041A60C 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x12_lpForm_KeyUp               dd 0                                    ; Ptr to Form KeyUp Event Code.
.text:0041A610 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x13_lpForm_LostFocus           dd 0                                    ; Ptr to Form LostFocus Event Code.
.text:0041A614 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x14_lpForm_MouseDown           dd 0                                    ; Ptr to Form MouseDown Event Code.
.text:0041A618 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x15_lpForm_MouseMove           dd 0                                    ; Ptr to Form MouseMove Event Code.
.text:0041A61C 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x16_lpForm_MouseUp             dd 0                                    ; Ptr to Form MouseUp Event Code.
.text:0041A620 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x17_lpForm_Paint               dd 0                                    ; Ptr to Form Paint Event Code.
.text:0041A624 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x18_lpForm_Initialize          dd 0                                    ; Ptr to Form Initialize Event Code.
.text:0041A628 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x19_lpForm_Terminate           dd 0                                    ; Ptr to Form Terminate Event Code.
.text:0041A62C 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1A_lpForm_OLEDragOver         dd 0                                    ; Ptr to Form OLEDragOver Event Code.
.text:0041A630 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1B_lpForm_OLEDragDrop         dd 0                                    ; Ptr to Form OLEDragDrop Event Code.
.text:0041A634 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1C_lpForm_OLEGiveFeedback     dd 0                                    ; Ptr to Form OLEGiveFeedback Event Code.
.text:0041A638 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1D_lpForm_OLEStartDrag        dd 0                                    ; Ptr to Form OLEStartDrag Event Code.
.text:0041A63C 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1E_lpForm_OLESetData          dd 0                                    ; Ptr to Form OLESetData Event Code.
.text:0041A640 00 00 00 00 _O_Pub_Obj_Inf1_Ctl_Inf0x1A_0x1F_lpForm_OLECompleteDrag     dd 0                                    ; Ptr to Form OLECompleteDrag Event Code.

