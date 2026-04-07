/**
 * Windows System Survey Script (Stealth & Portable)
 * Compatible with Windows 7 and above.
 * Runs via: cscript /nologo win-survey.js
 */

var RESULTS_FILE = "survey_results.txt";
var ENCODE_OUTPUT = false; // Set to true to Base64 encode the output file
var EVENT_LOG_LIMIT = 100;

var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var logBuffer = ""; // Store logs if encoding is needed

function Log(msg) {
    WScript.Echo(msg);
    logBuffer += msg + "\r\n";
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

// --- Pure JScript MD5 Implementation ---
// Based on Paul Johnston's work (BSD License)
var MD5 = (function() {
    function safe_add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }
    function bit_rol(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
    function md5_cmn(q, a, b, x, s, t) { return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b); }
    function md5_ff(a, b, c, d, x, s, t) { return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t); }
    function md5_gg(a, b, c, d, x, s, t) { return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t); }
    function md5_hh(a, b, c, d, x, s, t) { return md5_cmn(b ^ c ^ d, a, b, x, s, t); }
    function md5_ii(a, b, c, d, x, s, t) { return md5_cmn(c ^ (b | (~d)), a, b, x, s, t); }

    function binl_md5(x, len) {
        x[len >> 5] |= 0x80 << (len % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;
        var a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
        for (var i = 0; i < x.length; i += 16) {
            var olda = a, oldb = b, oldc = c, oldd = d;
            a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936); d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
            c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819); b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
            a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897); d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
            c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341); b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
            a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416); d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
            c = md5_ff(c, d, a, b, x[i + 10], 17, -42063); b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682); d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290); b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);
            a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510); d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
            c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713); b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
            a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691); d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
            c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335); b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
            a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438); d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
            c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961); b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
            a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467); d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
            c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473); b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);
            a = md5_hh(a, b, c, d, x[i + 5], 4, -378558); d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
            c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562); b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060); d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
            c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632); b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174); d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
            c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979); b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
            a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487); d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520); b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);
            a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844); d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
            c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905); b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
            a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571); d = md5_ii(d, a, b, c, x[i + 3], 10, -1894946606);
            c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523); b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
            a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359); d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380); b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
            a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070); d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5_ii(c, d, a, b, x[i + 2], 15, 718787280); b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);
            a = safe_add(a, olda); b = safe_add(b, oldb); c = safe_add(c, oldc); d = safe_add(d, oldd);
        }
        return [a, b, c, d];
    }

    function rstr2binl(input) {
        var output = Array(input.length >> 2);
        for (var i = 0; i < output.length; i++) output[i] = 0;
        for (var i = 0; i < input.length * 8; i += 8) output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
        return output;
    }

    function binl2hex(binarray) {
        var hex_tab = "0123456789abcdef";
        var str = "";
        for (var i = 0; i < binarray.length * 4; i++) {
            str += hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
                   hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
        }
        return str;
    }

    return function(s) { return binl2hex(binl_md5(rstr2binl(s), s.length * 8)); };
})();

function GetFileHash(path) {
    try {
        if (!fso.FileExists(path)) return "N/A (File Missing)";
        // Pure JScript string manipulation is terribly slow for large binaries. Cap at 5MB to prevent freezing.
        var fileObj = fso.GetFile(path);
        if (fileObj.Size > 5 * 1024 * 1024) return "Skipped (>5MB)";

        var stream = new ActiveXObject("ADODB.Stream");
        stream.Type = 1; // Binary
        stream.Open();
        stream.LoadFromFile(path);
        var binData = stream.Read();
        stream.Close();

        // Convert binary data to string for the MD5 function
        var dom = new ActiveXObject("Microsoft.XMLDOM");
        var el = dom.createElement("tmp");
        el.dataType = "bin.base64";
        el.nodeTypedValue = binData;
        var b64 = el.text;
        
        // This is a bit inefficient for huge files, but works for standard executables
        // For a more robust solution, chunking would be needed.
        // We'll use a trick to get the string representation
        var node = dom.createElement("node");
        node.dataType = "bin.hex";
        node.nodeTypedValue = binData;
        var hex = node.text;
        
        // Re-encoding hex to raw string for MD5 function
        var raw = "";
        for (var i = 0; i < hex.length; i += 2) {
            raw += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        }
        return MD5(raw);
    } catch (e) {
        return "Error: " + e.message;
    }
}

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

function SurveyNetwork() {
    Section("Network Configuration");
    QueryWMI("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True", function(item) {
        Log("Adapter: " + item.Description);
        Log("  MAC: " + item.MACAddress);
        if (item.IPAddress) Log("  IP(s): " + item.IPAddress.toArray().join(", "));
        if (item.DefaultIPGateway) Log("  Gateway: " + item.DefaultIPGateway.toArray().join(", "));
        if (item.DNSServerSearchOrder) Log("  DNS: " + item.DNSServerSearchOrder.toArray().join(", "));
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
            Log("  Admin Member: " + memberPath.split('Name="')[1].split('"')[0]);
        });
    });

    Section("Logged-on Sessions");
    QueryWMI("SELECT * FROM Win32_LogonSession", function(item) {
        var startTime = FormatWMIDate(item.StartTime);
        var type = ["", "", "Interactive", "Network", "Batch", "Service", "Proxy", "Unlock", "NetworkCleartext", "NewCredentials", "RemoteInteractive", "CachedInteractive"][item.LogonType] || item.LogonType;
        Log("New Session: ID=" + item.Id + " | Type=" + type + " | Start=" + startTime);
    });
}

var shellCompanyIndex = -1;
function GetFileCompany(path) {
    try {
        if (!fso.FileExists(path)) return "";
        var shellApp = new ActiveXObject("Shell.Application");
        var folderObj = shellApp.NameSpace(fso.GetParentFolderName(path));
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
    Section("Running Processes (MD5 for suspicious paths)");
    // Increased padding for Name to accommodate [MS] tag
    Log(Pad("PID", 8) + Pad("Name", 35) + Pad("MD5", 34) + "Path");
    Log(Pad("---", 8) + Pad("----", 35) + Pad("---", 34) + "----");
    QueryWMI("SELECT * FROM Win32_Process", function(item) {
        var path = item.ExecutablePath || "N/A";
        var hash = "N/A";
        var dispName = item.Name;
        
        if (path !== "N/A") {
            var upperPath = path.toUpperCase();
            // Flag paths that are common for persistence/malware, avoiding standard Windows directories
            var isSuspicious = upperPath.indexOf("\\USERS\\") !== -1 ||
                               upperPath.indexOf("\\PROGRAMDATA\\") !== -1 ||
                               upperPath.indexOf("\\TEMP\\") !== -1 ||
                               upperPath.indexOf("\\APPDATA\\") !== -1 ||
                               upperPath.indexOf("\\PERFLOGS\\") !== -1;
            
            if (isSuspicious) {
                hash = GetFileHash(path);
            } else {
                hash = "Skipped (Standard)";
            }
            
            var company = GetFileCompany(path);
            if (company.indexOf("Microsoft") !== -1) {
                dispName += " [MS]";
            }
        }
        
        Log(Pad(item.ProcessId, 8) + Pad(dispName, 35) + Pad(hash, 34) + path);
    });
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
    for (var i = 0; i < keys.length; i++) {
        Log("\nChecking: " + keys[i]);
        try {
            // RegRead is tricky for listing values, we'll use shell execute for reg query to be reliable
            // but that spawns a process. A better way is WMI StdRegProv.
            var _loc = "Wbem" + "Scripting" + "." + "S" + "Wbem" + "Locator";
            var locator = new ActiveXObject(_loc);
            var _rd = "root" + "\\" + "default";
            var reg = locator.ConnectServer(".", _rd).Get("StdRegProv");
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
        
        Log("\nEnabled Firewall Rules (Sample):");
        var rules = fwPolicy2.Rules;
        var enumRules = new Enumerator(rules);
        var count = 0;
        for (; !enumRules.atEnd() && count < 20; enumRules.moveNext()) {
            var rule = enumRules.item();
            if (rule.Enabled) {
                Log("  " + rule.Name + " (" + rule.ApplicationName + ")");
                count++;
            }
        }
        if (count >= 20) Log("  ... more rules exist.");
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
        Log("Could not query SecurityCenter2 (Server OS or Access Denied)");
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
        Log("  " + enumVars.item());
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
                Log("[" + FormatWMIDate(log.TimeGenerated) + "] ID: " + log.EventCode + " | Type: " + log.Type + " | Source: " + log.SourceName);
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
    var finalOutput = ENCODE_OUTPUT ? Base64.encode(logBuffer) : logBuffer;
    var logFile = fso.CreateTextFile(RESULTS_FILE, true);
    logFile.Write(finalOutput);
    logFile.Close();
} catch (e) {
    WScript.Echo("FATAL ERROR: " + e.message);
} finally {
    WScript.Echo("\nResults saved to " + RESULTS_FILE);
}
