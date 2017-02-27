/*
  VBDllCall (c) lallous <lallousx86(at)yahoo.com>

  You may use this library free of charge as long as you keep appropriate copyright and credits.

03/23/2004 04:28 PM -
 * Made appropriate use of Message() as if C's printf()

07/19/2004 08:03 AM
 * Now if DllFunctionCall is referenced from outside a function, the script will try to create a function first

09/30/2004 06:19 PM
 * changed all messages so that they display appropriate "ea" that allows one to double-click in msg window
 * integrated changes done by Dmitry Friesen <-- thanks for your collaboration

Todo
-----
* Perhaps make a summary as: DLL1 has n1 functions, DLL2 has n2 functions ... (use SetHashString associative array)
* upon script's start, an option box should show with a list of options

*/

#include <idc.idc>
#include <common.idc>

static FunctionStart(ea)
{
  return LocByName(GetFunctionName(ea));
}

static VBDllCall(functionBody)
{
  auto dll, fnc, fncEa, ea, x, oldfncname, newfncname, dllname, oldprm;

  // Try to get function's start
  fncEa = FunctionStart(functionBody);

  // Not in a function, we try to create a function
  if (fncEa == BADADDR)
  {
    // Try to locate / make function
    ea = functionBody;

    // skip some lines
    for (x=0;x<6;x++)
      ea = PrevHead(ea, 0);

    // Is this a valid VBDllCall?
    if ((Byte(ea) == 0xA1) && (Byte(functionBody+3) == 0xE0))
    {
      if (MakeFunction(ea, functionBody+3) == 0)
      {
        Message("%X: Failed while attempting to create a VBDllCall function!\n", ea);
        return 0;
      }

      // now get the function start again
      fncEa = FunctionStart(functionBody);
      Message("%X: Created a new VBDllCall function, now trying to name it!\n", fncEa);
    }
    else
    {
      Message("%X: must be called from inside a valid VBDllCall function!\n", functionBody);
      return 0;
    }
  }

  ea = fncEa;

  // skip some instructions
  for (x=0;x<4;x++)
    ea = NextHead(ea, BADADDR);
  
  // check if valid signature
  if (Byte(ea) != 0x68)
  {
    Message("%X: not a valid DllFunctionCall signature\n", ea);
    return 0;
  }

  // get the value @ push XXXX
  x = GetOperandValue(ea, 0);

  // point to DLL name
  dll = Dword(x);

  // point to function name
  fnc = Dword(x + 4);

  // get name of new function
  newfncname = getCName(fnc);

  // get the name of the DLL
  dllname = getCName(dll);

  // get old function name
  oldfncname = GetFunctionName(fncEa);

  // get value of dword ptr: mov eax, dword_xxxxx
  x = GetOperandValue(fncEa, 1);

  if ((x != BADADDR) && (strstr(Name(x), "dword") != -1))
  {
    // rename the 'dword' that points to the API
		MakeName(x, "pfn_" + newfncname);
		MakeDword(x - 8);
		MakeDword(x - 4);
		MakeName(x - 8, "hLib_" + dllname + "_" + newfncname);
  }

  // check if already named something similar to the new name
  if (strstr(oldfncname, newfncname) >= 0)
  {
    Message("%x: %s is already named as something relevant!\n", fncEa, oldfncname);
    return 0;
  }

  
	// Take default string type
  // Change string type to C style
  oldprm = GetLongPrm(INF_STRTYPE);
	SetLongPrm(INF_STRTYPE, ASCSTR_C);

  // make DLL name string
  MakeUnkn(dll, 0);
  MakeStr(dll, BADADDR);

  // make function name string
  MakeUnkn(fnc, 0);
  MakeStr(fnc, BADADDR);

  // rename function
  MakeName(fncEa, newfncname);

  // set function's non-repeatable comments
  SetFunctionCmt(fncEa, dllname + "." + newfncname, 0);

  // restore old string type
  SetLongPrm(INF_STRTYPE, oldprm);

  Message("%X: %s is renamed to %s.%s\n", fncEa, oldfncname, dllname, newfncname);
  return 1;
}

static main()
{
  auto x, y, c, ea, version;

  version = "v0.1.2";

  x = LocByName("DllFunctionCall");

  if (x == BADADDR)
  {
    Message("No reference to VB's DllFunctionCall()...script aborted...\n");
    return;
  }

  Message("VBDllCall %s loaded... searching for functions to be renamed....\n", version);
  c = 0;
  for (y=RfirstB(x); y != BADADDR; y = RnextB(x,y) )
  {
    if (XrefType() != fl_CN)
      continue;
    if (VBDllCall(y))
      c++;
  }
  Message("%d VB Dll function calls encountered and named appropriately!\n", c);
}