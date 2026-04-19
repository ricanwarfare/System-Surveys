/**
 * Windows System Survey Script (Stealth & Portable)
 * Compatible with Windows 7 and above.
 * Runs via: cscript /nologo win-survey.js
 */

var RESULTS_FILE = ""; // Empty = auto-generate with hostname
var ENCODE_OUTPUT = false; // Set to true to Base64 encode the output file
var EVENT_LOG_LIMIT = 100;
var ENABLE_PROCESS_HASHING = true; // Use certutil to hash all processes limitlessly

var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var logBuffer = ""; // Store logs if encoding is needed

function Log(msg) {
    WScript.Echo(msg);
    logBuffer += msg + "\r\n";
}

function EscapeBatch(str) {
    return str.replace(/([&|^<>"])/g, "^$1");
}

function SafeEnvValue(key, value) {
    var sensitivePattern = /key|secret|password|passwd|token|credential|private|auth/i;
    if (sensitivePattern.test(key)) {
        return value.length > 4 ? value.substring(0, 4) + "********" : "****";
    }
    return value;
}

function RandomSuffix() {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var result = "";
    for (var i = 0; i < 8; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// --- Base64 Implementation ---
var Base64 = (function() {
    var keys = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    return {
        encode: function(input) {
            var output = "";
            var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
            var i = 0;
            while (i < input.length) {
                chr1 = input.charCodeAt(i++);
                chr2 = input.charCodeAt(i++);
                chr3 = input.charCodeAt(i++);
                enc1 = chr1 >> 2;
                enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
                enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
                enc4 = chr3 & 63;
                if (isNaN(chr2)) enc3 = enc4 = 64;
                else if (isNaN(chr3)) enc4 = 64;
                output += keys.charAt(enc1) + keys.charAt(enc2) + keys.charAt(enc3) + keys.charAt(enc4);
            }
            return output;
        }
    };
})();

function FormatWMIDate(wmiDate) {
    if (!wmiDate) return "N/A";
    return wmiDate.substring(0, 4) + "-" + wmiDate.substring(4, 6) + "-" + wmiDate.substring(6, 8) + " " +
           wmiDate.substring(8, 10) + ":" + wmiDate.substring(10, 12) + ":" + wmiDate.substring(12, 14);
}

function Pad(str, len) {
    str = String(str);
    while (str.length < len) str += " ";
    return str;
}

function Section(title) {
    var line = "--------------------------------------------------------------------------------";
    var border = "################################################################################";
    Log("\n" + border);
    Log("#  " + title.toUpperCase());
    Log(border + "\n");
}

// MD5 engine removed. Using certutil mapping instead.

// GetFileHash removed; hashing is now optimally batched within SurveyProcesses.

// --- WMI Helpers (Obfuscated Strings) ---
var _w = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "cim" + "v2";
var wmi = GetObject(_w);

function QueryWMI(query, callback) {
    try {
        var items = wmi.ExecQuery(query);
        var enumItems = new Enumerator(items);
        for (; !enumItems.atEnd(); enumItems.moveNext()) {
            callback(enumItems.item());
        }
    } catch (e) {
        Log("WMI Error [" + query + "]: " + e.message);
    }
}

// ... survey modules below ...

// --- Survey Modules ---

function SurveySystemInfo() {
    Section("System Information");
    QueryWMI("SELECT * FROM Win32_OperatingSystem", function(item) {
        Log("Host Name: " + item.CSName);
        Log("OS: " + item.Caption + " (" + item.Version + ")");
        Log("Architecture: " + item.OSArchitecture);
        Log("Install Date: " + FormatWMIDate(item.InstallDate));
        Log("Registered User: " + item.RegisteredUser);
        Log("Last Boot: " + FormatWMIDate(item.LastBootUpTime));
    });
    QueryWMI("SELECT * FROM Win32_ComputerSystem", function(item) {
        Log("Model: " + item.Manufacturer + " " + item.Model);
        Log("Domain: " + item.Domain);
        Log("Total Memory: " + Math.round(item.TotalPhysicalMemory / 1024 / 1024) + " MB");
    });
}

function SafeArray(arr) {
    // Safely convert WMI SafeArray to JScript array
    // WMI returns SafeArrays that sometimes fail .toArray() on Win11/WSH
    try {
        if (!arr || arr === null) return [];
        if (typeof arr === 'unknown') {
            // Try VBArray conversion as fallback
            try { return new VBArray(arr).toArray(); } catch(e2) { return []; }
        }
        if (typeof arr.toArray === 'function') return arr.toArray();
        if (typeof arr === 'string') return [arr];
        return [arr];
    } catch (e) {
        return [];
    }
}

function SurveyNetwork() {
    Section("Network Configuration");
    QueryWMI("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True", function(item) {
        Log("Adapter: " + item.Description);
        Log("  MAC: " + (item.MACAddress || "N/A"));
        
        var ips = SafeArray(item.IPAddress);
        var masks = SafeArray(item.IPSubnet);
        if (ips.length > 0) {
            for (var i = 0; i < ips.length; i++) {
                Log("  IP: " + ips[i] + (masks[i] ? " (" + masks[i] + ")" : ""));
            }
        } else {
            Log("  IP: N/A");
        }
        
        var gateways = SafeArray(item.DefaultIPGateway);
        if (gateways.length > 0) {
            Log("  Gateway: " + gateways.join(", "));
        }
        
        var dns = SafeArray(item.DNSServerSearchOrder);
        if (dns.length > 0) {
            Log("  DNS: " + dns.join(", "));
        } else {
            Log("  DNS: N/A");
        }
        
        Log("  DHCP: " + (item.DHCPEnabled ? "Yes" : "No") + (item.DHCPServer ? " (" + item.DHCPServer + ")" : ""));
    });

    Section("Network Shares");
    QueryWMI("SELECT * FROM Win32_Share", function(item) {
        Log(item.Name + " => " + item.Path + " [" + item.Description + "]");
    });
}

function SurveyUsers() {
    Section("Local Users");
    QueryWMI("SELECT * FROM Win32_UserAccount", function(item) {
        Log(item.Name + " (Disabled: " + item.Disabled + ", Locked: " + item.Lockout + ", SID: " + item.SID + ")");
    });

    Section("Administrators Group Members");
    // SID S-1-5-32-544 is the built-in Administrators group
    QueryWMI("SELECT * FROM Win32_Group WHERE SID = 'S-1-5-32-544'", function(group) {
        // Find members via association
        var query = "SELECT * FROM Win32_GroupUser WHERE GroupComponent = \"Win32_Group.Domain='" + group.Domain + "',Name='" + group.Name + "'\"";
        QueryWMI(query, function(assoc) {
            // PartComponent is the user/group reference
            var memberPath = assoc.PartComponent; 
            var nameMatch = memberPath.match(/Name="([^"]+)"/);
            if (nameMatch) {
                Log("  Admin Member: " + nameMatch[1]);
            } else {
                Log("  Admin Member: " + memberPath); // Fallback: log raw path
            }
        });
    });

    Section("Logged-on Sessions");
    QueryWMI("SELECT * FROM Win32_LogonSession", function(item) {
        var startTime = FormatWMIDate(item.StartTime);
        var logonType = (typeof item.LogonType === 'number' && item.LogonType > 0) ? item.LogonType : 0;
        var typeMap = {
            2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
            6: "Proxy", 7: "Unlock", 8: "NetworkCleartext",
            9: "NewCredentials", 10: "RemoteInteractive", 11: "CachedInteractive"
        };
        var type = typeMap[logonType] || (logonType > 0 ? "Type" + logonType : "Unknown");
        var sessionId = item.LogonId || item.Id || "N/A";
        Log("Session: ID=" + sessionId + " | Type=" + type + " | Start=" + startTime);
    });
}

var shellCompanyIndex = -1;
var globalShellApp = null;
function GetFileCompany(path) {
    try {
        if (!fso.FileExists(path)) return "";
        if (!globalShellApp) globalShellApp = new ActiveXObject("Shell.Application");
        var folderObj = globalShellApp.NameSpace(fso.GetParentFolderName(path));
        if (!folderObj) return "";
        var itemObj = folderObj.ParseName(fso.GetFileName(path));
        
        if (shellCompanyIndex === -1) {
            for (var i = 0; i < 50; i++) {
                var header = folderObj.GetDetailsOf(null, i);
                if (header && (header.toLowerCase() === "company" || header.toLowerCase() === "compañía")) {
                    shellCompanyIndex = i;
                    break;
                }
            }
            if (shellCompanyIndex === -1) shellCompanyIndex = 33;
        }
        return folderObj.GetDetailsOf(itemObj, shellCompanyIndex) || "";
    } catch(e) {
        return "";
    }
}

function SurveyProcesses() {
    Section("Running Processes (SHA-1 Hashing)");
    var processes = [];
    var uniquePaths = {};
    
    // 1. Collect all running processes
    QueryWMI("SELECT * FROM Win32_Process", function(item) {
        var path = item.ExecutablePath || "N/A";
        if (path !== "N/A" && !uniquePaths[path]) {
            uniquePaths[path] = true;
        }
        processes.push({
            PID: item.ProcessId,
            Name: item.Name,
            Path: path
        });
    });
    
    // 2. Batch hash unique paths via a single background cmd process
    var hashMap = {};
    if (ENABLE_PROCESS_HASHING) {
        try {
            var tempDir = shell.ExpandEnvironmentStrings("%TEMP%");
            var batPath = tempDir + "\\sys_hash_" + RandomSuffix() + ".bat";
            var outPath = tempDir + "\\sys_hash_out_" + RandomSuffix() + ".txt";
            
            var batFile = fso.CreateTextFile(batPath, true);
            batFile.WriteLine("@echo off");
            for (var p in uniquePaths) {
                if (fso.FileExists(p)) {
                    batFile.WriteLine('certutil -hashfile "' + EscapeBatch(p) + '" SHA1');
                }
            }
            batFile.Close();
            
            // Run entirely hidden (0) and wait to return (true)
            shell.Run('cmd.exe /c "' + batPath + '" > "' + outPath + '" 2>&1', 0, true);
            
            if (fso.FileExists(outPath)) {
                var outFile = fso.OpenTextFile(outPath, 1);
                var output = outFile.AtEndOfStream ? "" : outFile.ReadAll();
                outFile.Close();
                
                var lines = output.split('\n');
                var currentPath = null;
                var hashBuffer = "";
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i].replace(/\r/g, "");
                    // CertUtil outputs: "SHA1 hash of C:\path\file.exe:\n<hash>\n  CertUtil: -hashfile command completed successfully."
                    // SHA-1 is 40 hex chars — always on one line, no wrapping
                    // On some Windows versions, the hash may be split across multiple lines
                    if (line.indexOf("hash of ") !== -1) {
                        // Extract path from "SHA1 hash of C:\path\file.exe:"
                        var hashOfIdx = line.indexOf("hash of ");
                        // The path goes from after "hash of " to end of line (may end with colon)
                        var pathPart = line.substring(hashOfIdx + 8);
                        // Remove trailing colon if present
                        if (pathPart.charAt(pathPart.length - 1) === ':') pathPart = pathPart.substring(0, pathPart.length - 1);
                        currentPath = pathPart;
                        hashBuffer = "";
                    } else if (currentPath) {
                        // Accumulate hash characters (may be split across lines)
                        var cleaned = line.replace(/\s/g, "");
                        if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length > 0) {
                            hashBuffer += cleaned.toLowerCase();
                            // SHA-1 is exactly 40 hex chars
                            if (hashBuffer.length === 40) {
                                hashMap[currentPath.toLowerCase()] = hashBuffer;
                                currentPath = null;
                                hashBuffer = "";
                            }
                        } else if (cleaned.length === 0) {
                            // Empty line — skip
                        } else {
                            // Not a hash line — reset
                            currentPath = null;
                            hashBuffer = "";
                        }
                    }
                }
            }
        } catch(e) {
            Log("Error during batch hashing: " + e.message);
        } finally {
            // Always clean up temp files
            if (typeof outPath !== 'undefined' && fso.FileExists(outPath)) {
                try { fso.DeleteFile(outPath); } catch(e2) {}
            }
            if (typeof batPath !== 'undefined' && fso.FileExists(batPath)) {
                try { fso.DeleteFile(batPath); } catch(e2) {}
            }
        }
    }
    
    // 3. Output results
    Log(Pad("PID", 8) + Pad("Name", 35) + Pad("SHA-1", 42) + "Path");
    Log(Pad("---", 8) + Pad("----", 35) + Pad("-----", 42) + "----");
    
    for (var j = 0; j < processes.length; j++) {
        var p = processes[j];
        var dispName = p.Name;
        var hash = "N/A";
        
        if (p.Path !== "N/A") {
            if (ENABLE_PROCESS_HASHING) {
                hash = hashMap[p.Path.toLowerCase()] || "N/A";
            } else {
                hash = "Skipped (Disabled)";
            }
            
            var company = GetFileCompany(p.Path);
            if (company.indexOf("Microsoft") !== -1) {
                dispName += " [MS]";
            }
        }
        
        Log(Pad(p.PID, 8) + Pad(dispName, 35) + Pad(hash, 66) + p.Path);
    }
}

function SurveyServices() {
    Section("Services");
    Log(Pad("Name", 30) + Pad("Status", 10) + Pad("State", 12) + Pad("StartMode", 12) + "DisplayName");
    Log(Pad("----", 30) + Pad("------", 10) + Pad("-----", 12) + Pad("---------", 12) + "-----------");
    QueryWMI("SELECT * FROM Win32_Service", function(item) {
        Log(Pad(item.Name, 30) + Pad(item.Status, 10) + Pad(item.State, 12) + Pad(item.StartMode.substring(0, 12), 12) + item.DisplayName);
    });
}

function SurveyStartup() {
    Section("Startup Keys");
    var keys = [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    ];
    var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
    var locator = new ActiveXObject(_loc);
    var _rd = "root" + "\\" + "default";
    var reg = locator.ConnectServer(".", _rd).Get("StdRegProv");

    for (var i = 0; i < keys.length; i++) {
        Log("\nChecking: " + keys[i]);
        try {
            var hDefKey = (keys[i].indexOf("HKLM") === 0) ? 0x80000002 : 0x80000001;
            var subKey = keys[i].substr(5);
            
            var method = reg.Methods_.Item("EnumValues");
            var inParams = method.InParameters.SpawnInstance_();
            inParams.hDefKey = hDefKey;
            inParams.sSubKeyName = subKey;
            
            var outParams = reg.ExecMethod_(method.Name, inParams);
            if (outParams.sNames !== null) {
                var names = outParams.sNames.toArray();
                for (var j = 0; j < names.length; j++) {
                    var valMethod = reg.Methods_.Item("GetStringValue");
                    var valIn = valMethod.InParameters.SpawnInstance_();
                    valIn.hDefKey = hDefKey;
                    valIn.sSubKeyName = subKey;
                    valIn.sValueName = names[j];
                    var valOut = reg.ExecMethod_(valMethod.Name, valIn);
                    Log("  " + names[j] + " => " + valOut.sValue);
                }
            } else {
                Log("  (No values found)");
            }
        } catch (e) {
            Log("  Error reading " + keys[i] + ": " + e.message);
        }
    }
}

function SurveyScheduledTasks() {
    Section("Scheduled Tasks");
    try {
        var service = new ActiveXObject("Schedule.Service");
        service.Connect();
        var rootFolder = service.GetFolder("\\");
        
        function EnumTasks(folder) {
            var tasks = folder.GetTasks(0);
            for (var i = 1; i <= tasks.Count; i++) {
                var t = tasks.Item(i);
                Log(t.Path + " [Enabled: " + t.Enabled + ", State: " + t.State + "]");
            }
            var subfolders = folder.GetFolders(0);
            for (var j = 1; j <= subfolders.Count; j++) {
                EnumTasks(subfolders.Item(j));
            }
        }
        EnumTasks(rootFolder);
    } catch (e) {
        Log("Error querying Scheduled Tasks: " + e.message);
    }
}

function SurveyFirewall() {
    Section("Firewall Settings & Rules");
    try {
        // NetFwPolicy2 is available on Win7+
        var fwPolicy2 = new ActiveXObject("HNetCfg.FwPolicy2");
        Log("Domain Profile Enabled: " + fwPolicy2.FirewallEnabled(1));
        Log("Private Profile Enabled: " + fwPolicy2.FirewallEnabled(2));
        Log("Public Profile Enabled: " + fwPolicy2.FirewallEnabled(4));
        
        Log("\nEnabled Firewall Rules:");
        var rules = fwPolicy2.Rules;
        var enumRules = new Enumerator(rules);
        var enabledRules = [];
        for (; !enumRules.atEnd(); enumRules.moveNext()) {
            var rule = enumRules.item();
            if (rule.Enabled) {
                enabledRules.push(rule);
            }
        }
        
        // Sort by name for consistent output
        enabledRules.sort(function(a, b) { return a.Name < b.Name ? -1 : 1; });
        
        if (enabledRules.length > 0) {
            Log("  " + Pad("Name", 40) + Pad("Direction", 12) + Pad("Action", 10) + Pad("Protocol", 10) + Pad("Ports", 20));
            Log("  " + Pad("----", 40) + Pad("---------", 12) + Pad("------", 10) + Pad("--------", 10) + Pad("-----", 20));
            for (var i = 0; i < enabledRules.length; i++) {
                var r = enabledRules[i];
                var dir = (r.Direction === 1) ? "In" : "Out";
                var act = (r.Action === 1) ? "Block" : "Allow";
                var proto = r.Protocol;
                // Protocol numbers to names
                if (proto === 1) proto = "ICMP";
                else if (proto === 6) proto = "TCP";
                else if (proto === 17) proto = "UDP";
                else if (proto === 47) proto = "GRE";
                else if (proto === 58) proto = "ICMPv6";
                var ports = r.LocalPorts || "Any";
                var name = r.Name ? r.Name.substring(0, 39) : "Unknown";
                Log("  " + Pad(name, 40) + Pad(dir, 12) + Pad(act, 10) + Pad(proto, 10) + Pad(String(ports).substring(0, 19), 20));
            }
            Log("\n  Total enabled rules: " + enabledRules.length);
        } else {
            Log("  No enabled firewall rules found.");
        }
    } catch (e) {
        Log("Error querying Firewall: " + e.message);
    }
}

function SurveyWMIPersistence() {
    Section("WMI Event Subscriptions (Persistence)");
    try {
        var _sub = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "sub" + "scription";
        var subWmi = GetObject(_sub);
        var classes = ["__EventFilter", "__EventConsumer", "__FilterToConsumerBinding"];
        for (var i = 0; i < classes.length; i++) {
            Log("\nClass: " + classes[i]);
            var items = subWmi.ExecQuery("SELECT * FROM " + classes[i]);
            var enumItems = new Enumerator(items);
            var count = 0;
            for (; !enumItems.atEnd(); enumItems.moveNext()) {
                var item = enumItems.item();
                Log("  Name: " + (item.Name || "Unnamed") + " | Path: " + item.Path_);
                count++;
            }
            if (count === 0) Log("  (None found)");
        }
    } catch (e) {
        Log("Error querying WMI persistence: " + e.message);
    }
}

function SurveyPSHistory() {
    Section("PowerShell History Check");
    try {
        var userDir = "C:\\Users";
        if (fso.FolderExists(userDir)) {
            var folders = fso.GetFolder(userDir).SubFolders;
            var enumFolders = new Enumerator(folders);
            for (; !enumFolders.atEnd(); enumFolders.moveNext()) {
                var folder = enumFolders.item();
                var histPath = folder.Path + "\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt";
                if (fso.FileExists(histPath)) {
                    var lastMod = fso.GetFile(histPath).DateLastModified;
                    Log("Found: " + histPath + " | Last Modified: " + lastMod);
                }
            }
        }
    } catch (e) {
        Log("Error checking PS History: " + e.message);
    }
}

function SurveySecurityProducts() {
    Section("Security Product Status (AV/EDR)");

    // Check if this is a server OS (SecurityCenter2 is client-only)
    var isServerOS = false;
    QueryWMI("SELECT * FROM Win32_OperatingSystem", function(item) {
        if (item.ProductType && item.ProductType !== "1") {
            isServerOS = true;
        }
    });

    try {
        // SecurityCenter2 is client-only (Vista+)
        var _sc = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "Security" + "Center2";
        var scWmi = GetObject(_sc);
        var products = ["AntivirusProduct", "AntiSpywareProduct", "FirewallProduct"];
        for (var i = 0; i < products.length; i++) {
            var items = scWmi.ExecQuery("SELECT * FROM " + products[i]);
            var enumItems = new Enumerator(items);
            for (; !enumItems.atEnd(); enumItems.moveNext()) {
                var item = enumItems.item();
                Log(products[i] + ": " + item.displayName + " [State: " + item.productState + "]");
            }
        }
    } catch (e) {
        if (isServerOS) {
            Log("SecurityCenter2 is not available on Server OS (client-only namespace).");
        } else {
            Log("Error querying SecurityCenter2: " + e.message);
        }
    }
}

function SurveyHotfixes() {
    Section("Installed Hotfixes (Patches)");
    QueryWMI("SELECT * FROM Win32_QuickFixEngineering", function(item) {
        Log(item.HotFixID + " | InstalledOn: " + item.InstalledOn + " | Description: " + item.Description);
    });
}

function SurveyEnvVars() {
    Section("Environment Variables (Process level)");
    var vars = shell.Environment("PROCESS");
    var enumVars = new Enumerator(vars);
    for (; !enumVars.atEnd(); enumVars.moveNext()) {
        var item = enumVars.item();
        var eqPos = item.indexOf('=');
        if (eqPos !== -1) {
            var key = item.substring(0, eqPos);
            var value = item.substring(eqPos + 1);
            Log("  " + key + "=" + SafeEnvValue(key, value));
        } else {
            Log("  " + item);
        }
    }
}

function SurveyRemoteAccess() {
    Section("Remote Access Configuration");
    try {
        var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
        var locator = new ActiveXObject(_loc);
        var _rd = "root" + "\\" + "default";
        var reg = locator.ConnectServer(".", _rd).Get("StdRegProv");
        
        function GetRegVal(hDefKey, subKey, valName) {
            var vMethod = reg.Methods_.Item("GetDWORDValue");
            var vIn = vMethod.InParameters.SpawnInstance_();
            vIn.hDefKey = hDefKey;
            vIn.sSubKeyName = subKey;
            vIn.sValueName = valName;
            var vOut = reg.ExecMethod_(vMethod.Name, vIn);
            return (vOut.uValue === null) ? "N/A" : vOut.uValue;
        }

        var tsKey = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
        var fDeny = GetRegVal(0x80000002, tsKey, "fDenyTSConnections");
        Log("Remote Desktop (fDenyTSConnections): " + (fDeny === 0 ? "ENABLED" : (fDeny === 1 ? "DISABLED" : "N/A")));

        var winRMKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Service";
        var winRMEnc = GetRegVal(0x80000002, winRMKey, "allow_unencrypted");
        Log("WinRM Allow Unencrypted: " + winRMEnc);
    } catch (e) {
        Log("Error querying Remote Access registry: " + e.message);
    }
}

function SurveyDrivers() {
    Section("Kernel Drivers (Signed)");
    Log(Pad("Name", 30) + Pad("DeviceID", 40) + "Manufacturer");
    Log(Pad("----", 30) + Pad("--------", 40) + "------------");
    QueryWMI("SELECT * FROM Win32_PnPSignedDriver", function(item) {
        if (item.Manufacturer && item.Manufacturer.indexOf("Microsoft") === -1) {
            Log(Pad(item.FriendlyName || item.DeviceName, 30) + Pad(item.DeviceID.substring(0, 38), 40) + item.Manufacturer);
        }
    });
}

function SurveyNeighbors() {
    Section("Network Neighbors (ARP / Neighbor Cache)");
    try {
        var _wsm = "win" + "mgmts" + ":" + "\\\\" + ".\\" + "root" + "\\" + "standard" + "cim" + "v2";
        var wmiStd = GetObject(_wsm);
        var items = wmiStd.ExecQuery("SELECT * FROM MSFT_NetNeighbor");
        var enumItems = new Enumerator(items);
        Log(Pad("IP Address", 25) + "State");
        Log(Pad("----------", 25) + "-----");
        for (; !enumItems.atEnd(); enumItems.moveNext()) {
            var item = enumItems.item();
            Log(Pad(item.IPAddress, 25) + item.State);
        }
    } catch (e) {
        Log("MSFT_NetNeighbor not available (Old Windows or OS not supporting CIM v2)");
    }
}

function SurveyInstalledPrograms() {
    Section("Installed Programs (Fast Registry Query)");
    Log(Pad("Name", 60) + Pad("Version", 20) + "Publisher");
    Log(Pad("----", 60) + Pad("-------", 20) + "---------");

    var keys = [
        ["HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"],
        ["HKEY_LOCAL_MACHINE", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"],
        ["HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"]
    ];

    var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
    var locator = new ActiveXObject(_loc);
    var reg = locator.ConnectServer(".", "root\\default").Get("StdRegProv");

    for (var i = 0; i < keys.length; i++) {
        try {
            var hDefKey = (keys[i][0] === "HKEY_LOCAL_MACHINE") ? 0x80000002 : 0x80000001;
            var subKey = keys[i][1];
            
            var method = reg.Methods_.Item("EnumKey");
            var inParams = method.InParameters.SpawnInstance_();
            inParams.hDefKey = hDefKey;
            inParams.sSubKeyName = subKey;
            
            var outParams = reg.ExecMethod_(method.Name, inParams);
            if (outParams.sNames !== null) {
                var names = outParams.sNames.toArray();
                for (var j = 0; j < names.length; j++) {
                    var fullSubKey = subKey + "\\" + names[j];
                    
                    function GetRegVal(valName) {
                        var vMethod = reg.Methods_.Item("GetStringValue");
                        var vIn = vMethod.InParameters.SpawnInstance_();
                        vIn.hDefKey = hDefKey;
                        vIn.sSubKeyName = fullSubKey;
                        vIn.sValueName = valName;
                        var vOut = reg.ExecMethod_(vMethod.Name, vIn);
                        return vOut.sValue || "N/A";
                    }

                    var pName = GetRegVal("DisplayName");
                    if (pName !== "N/A") {
                        var pVer = GetRegVal("DisplayVersion");
                        var pPub = GetRegVal("Publisher");
                        Log(Pad(pName.substring(0, 58), 60) + Pad(pVer.substring(0, 18), 20) + pPub);
                    }
                }
            }
        } catch (e) {
            // Path might not exist on all architectures/users
        }
    }
}

function SurveyEventLogs() {
    Section("Event Logs (Last " + EVENT_LOG_LIMIT + " entries each)");
    var logs = ["System", "Security", "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"];
    
    for (var i = 0; i < logs.length; i++) {
        Log("\n--- Log: " + logs[i] + " ---");
        try {
            // WMI Win32_NTLogEvent
            // Note: Security log requires SeSecurityPrivilege
            var query = "SELECT * FROM Win32_NTLogEvent WHERE Logfile = '" + logs[i].replace(/'/g, "\\'") + "'";
            var items = wmi.ExecQuery(query);
            var enumItems = new Enumerator(items);
            var count = 0;
            
            // WMI doesn't easily support ORDER BY or LIMIT in standard SELECT * for event logs
            // So we iterate and stop. To get the 'latest', we'd need to manually sort or use a better query.
            // But standard WMI enumeration is usually sequential.
            for (; !enumItems.atEnd() && count < EVENT_LOG_LIMIT; enumItems.moveNext()) {
                var log = enumItems.item();
                Log("[" + FormatWMIDate(log.TimeGenerated) + "] ID: " + log.EventCode + " | Type: " + log.Type + " | Category: " + (log.CategoryString || log.Category || "N/A") + " | Source: " + log.SourceName);
                // Log("Message: " + log.Message.substr(0, 100) + "...");
                count++;
            }
            if (count === 0) Log("No logs found or access denied.");
        } catch (e) {
            Log("Error querying " + logs[i] + ": " + e.message);
        }
    }
}

// --- Main ---
try {
    // WSH deprecation warning
    if (typeof WScript !== "undefined") {
        WScript.Echo("NOTE: Windows Script Host (WSH) is deprecated by Microsoft.");
        WScript.Echo("Consider migrating to PowerShell for long-term compatibility.");
        WScript.Echo("");
    }

    // Parse command-line arguments
    var args = WScript.Arguments;
    var outputFileName = RESULTS_FILE;
    if (!outputFileName) {
        var hostName = ".";
        try { hostName = shell.ExpandEnvironmentStrings("%COMPUTERNAME%"); } catch(e) { hostName = "unknown"; }
        outputFileName = "survey_" + hostName + ".txt";
    }
    var encodeOutput = ENCODE_OUTPUT;
    var skipHashing = !ENABLE_PROCESS_HASHING;

    for (var a = 0; a < args.length; a++) {
        if (args(a) === "--output" && a + 1 < args.length) {
            outputFileName = args(a + 1); a++;
        } else if (args(a) === "--encode") {
            encodeOutput = true;
        } else if (args(a) === "--no-hash") {
            skipHashing = true;
        } else if (args(a) === "--help") {
            WScript.Echo("Usage: cscript /nologo win-survey.js [options]");
            WScript.Echo("  --output <file>   Output file path (default: survey_results.txt)");
            WScript.Echo("  --encode          Base64 encode the output");
            WScript.Echo("  --no-hash         Skip process hashing (faster)");
            WScript.Echo("  --help            Show this help");
            WScript.Quit(0);
        }
    }

    // Apply CLI overrides
    if (skipHashing) {
        ENABLE_PROCESS_HASHING = false;
    }

    Log("Starting System Survey at " + new Date());
    SurveySystemInfo();
    SurveyNetwork();
    SurveyUsers();
    SurveyProcesses();
    SurveyServices();
    SurveyStartup();
    SurveyScheduledTasks();
    SurveyWMIPersistence();
    SurveyPSHistory();
    SurveySecurityProducts();
    SurveyHotfixes();
    SurveyInstalledPrograms();
    SurveyEnvVars();
    SurveyRemoteAccess();
    SurveyDrivers();
    SurveyNeighbors();
    SurveyFirewall();
    SurveyEventLogs();
    Log("\nSurvey completed at " + new Date());
    
    // Final Write
    var finalOutput = encodeOutput ? Base64.encode(logBuffer) : logBuffer;
    var logFile = fso.CreateTextFile(outputFileName, true);
    logFile.Write(finalOutput);
    logFile.Close();
} catch (e) {
    WScript.Echo("FATAL ERROR: " + e.message);
} finally {
    WScript.Echo("\nResults saved to " + outputFileName);
}
